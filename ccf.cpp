#include <stdio.h>

#ifdef WIN32
#include <Ws2tcpip.h>
#include <Wspiapi.h>
#include <winsock2.h>
#include <windows.h>
#include <winbase.h>
#include <Xgetopt.h>
#else
#include <getopt.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <signal.h>

#ifndef WIN32
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#endif

#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <algorithm>

// libevent
#include "event.h"
#include "evhttp.h"

// JSON
#include "cJSON.h"

// NUI
#include "nuiDebugLogger.h"
#include "nuiDaemon.h"
#include "nuiPipeline.h"
#include "nuiModule.h"
#include "nuiFactory.h"
#include "nuiProperty.h"
#include "nuiDataStream.h"
#include "nuiDataGenericContainer.h"
#include "nuiMultimodalSyntaxTree.h"

#include "nuiTree.h"

#include "nuiJsonRpcApi.h"

// assert
#include <assert.h>
#include "../../libs/nuiFramework/inc/nuiFrameworkManager.h"

#define NUI_GUIDIR	"gui/html"

#ifdef WIN32
#define SLEEP( milliseconds ) Sleep( (DWORD) milliseconds ) 
#else
#define SLEEP( milliseconds ) usleep( (unsigned long) (milliseconds * 1000.0) )
#endif

LOG_DECLARE("App");

static bool want_quit = false;
static struct event_base *base = NULL;
static bool config_syslog = false;
static std::string config_guidir = NUI_GUIDIR;
static struct evhttp *server = NULL;
int g_config_delay = 20;

bool want_quit_soon = false;

char *strsep(char **stringp, const char *delim) {
	char *s = *stringp;
	char *e;
	if (!s)
		return NULL;
	e = strpbrk(s, delim);
	if (e)
		*e++ = '\0';
	*stringp = e;
	return s;
}

inline bool str_is_zero(const char* pStr)
{
    if((strlen(pStr) == 1) && (pStr[0] == '0'))
        return true;
    else
        return false;
}

//! returns 0 - MAX_INT integer in case of success, -1 in case of failure
inline int _atoi(const char* pStr)
{
    int res = atoi(pStr);
   
    if ( !str_is_zero(pStr) && (res==0) )
        return -1;
    else
        return res;
}

static void signal_term(int signal) 
{
	want_quit = true;
}

void web_json(struct evhttp_request *req, cJSON *root) {
	struct evbuffer *evb = evbuffer_new();
	char *out;

	out = cJSON_Print(root);

	evbuffer_add(evb, out, strlen(out));
	evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	evhttp_send_reply(req, HTTP_OK, "Everything is fine", evb);
	evbuffer_free(evb);

	free(out);
}

void web_error(struct evhttp_request *req, const char* message) 
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", 0);
    cJSON_AddStringToObject(root, "message", message);
    web_json(req, root);
}

void web_index(struct evhttp_request *req, void *arg) {
	evhttp_add_header(req->output_headers, "Location", "/gui/index.html");
	evhttp_send_reply(req, HTTP_MOVETEMP, "Everything is fine", NULL);
}

void web_file(struct evhttp_request *req, void *arg) {
	FILE *fd;
	int readidx = 0, ret;
	long filesize = 0;
	struct evbuffer *evb;
	char filename[256],
		 *buf, *uri, *baseuri;

	// web_file accept only file from gui
	if ( strstr(req->uri, "/gui/") != req->uri ) {
		evhttp_send_error(req, 404, "Not found");
		return;
	}

	if ( strstr(req->uri, "..") != NULL ) {
		evhttp_send_error(req, 403, "Security error");
		return;
	}

	uri = strdup(req->uri);
	if ( uri == NULL ) {
		LOG(NUI_ERROR, "unable to duplicate uri, memory missing ?");
		evhttp_send_error(req, 500, "Memory error");
		return;
	}

	baseuri = strsep(&uri, "?");

	snprintf(filename, sizeof(filename), "%s/%s",
		config_guidir.c_str(), baseuri + sizeof("/gui/") - 1);

	free(baseuri);

	LOG(NUI_DEBUG, "web: GET " << filename);
	fd = fopen(filename, "rb");
	if ( fd == NULL ) {
		evhttp_send_error(req, 404, "Not found");
		return;
	}

	fseek(fd, 0, SEEK_END);
	filesize = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	buf = (char*)malloc(filesize);
	if ( buf == NULL ) {
		fclose(fd);
		web_error(req, "memory error");
		return;
	}

	while ( readidx < filesize ) {
		ret = fread(&buf[readidx], 1, filesize - readidx, fd);
		if ( ret <= 0 ) {
			perror("guifile");
			return;
		}
		readidx += ret;
	}
	fclose(fd);

	if ( strncmp(filename + strlen(filename) - 2, "js", 2) == 0 )
		evhttp_add_header(req->output_headers, "Content-Type", "application/javascript");
	else if ( strncmp(filename + strlen(filename) - 3, "css", 3) == 0 )
		evhttp_add_header(req->output_headers, "Content-Type", "text/css");
	else if ( strncmp(filename + strlen(filename) - 3, "png", 3) == 0 )
		evhttp_add_header(req->output_headers, "Content-Type", "image/png");
	else if ( strncmp(filename + strlen(filename) - 3, "swf", 3) == 0 )
		evhttp_add_header(req->output_headers, "Content-Type", "application/x-shockwave-flash");
	else
		evhttp_add_header(req->output_headers, "Content-Type", "text/html");

	evb = evbuffer_new();
	evbuffer_add(evb, buf, filesize);

	evhttp_send_reply(req, HTTP_OK, "Everything is fine", evb);
	evbuffer_free(evb);
	free(buf);
}

cJSON* serialize_pipeline(nuiModuleDescriptor* descriptor);
cJSON* serialize_module(nuiModuleDescriptor* descriptor);
cJSON* serialize_endpoint(nuiEndpointDescriptor *descriptor);
cJSON* serialize_connection(nuiDataStreamDescriptor *descriptor);

cJSON* serialize_pipeline(nuiModuleDescriptor* descriptor)
{ 
    cJSON *data, *modules;
    
    data = data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "name", descriptor->getName().c_str());
    cJSON_AddStringToObject(data, "description", descriptor->getDescription().c_str());
    cJSON_AddStringToObject(data, "author", descriptor->getAuthor().c_str());

    cJSON_AddItemToObject(data, "modules", modules = cJSON_CreateArray());
    for(int i = 0 ; i<descriptor->getChildModulesCount() ; i++)
        cJSON_AddItemToArray(modules, serialize_module(descriptor->getChildModuleDescriptor(i)));
    
    cJSON *inputEndpoints;
    cJSON_AddItemToObject(data, "inputEndpoints", inputEndpoints = cJSON_CreateArray());
    for(int i=0 ; i<descriptor->getInputEndpointsCount() ; i++)
        cJSON_AddItemToArray(inputEndpoints, serialize_endpoint(descriptor->getInputEndpointDescriptor(i)));

    cJSON *outputEndpoints;
    cJSON_AddItemToObject(data, "outputEndpoints", outputEndpoints = cJSON_CreateArray());
    for(int i=0 ; i<descriptor->getOutputEndpointsCount() ; i++)
        cJSON_AddItemToArray(outputEndpoints, serialize_endpoint(descriptor->getOutputEndpointDescriptor(i)));

    cJSON *connections;
    cJSON_AddItemToObject(data, "connections", connections = cJSON_CreateArray());
    for (int i = 0 ; i<descriptor->getDataStreamDescriptorCount() ; i++)
        cJSON_AddItemToArray(connections, serialize_connection(descriptor->getDataStreamDescriptor(i)));

    return data;
}

cJSON* serialize_module(nuiModuleDescriptor* descriptor)
{
    cJSON *module = cJSON_CreateObject();

    cJSON_AddStringToObject(module, "name", descriptor->getName().c_str());
    cJSON_AddStringToObject(module, "author", descriptor->getAuthor().c_str());
    cJSON_AddStringToObject(module, "description", descriptor->getDescription().c_str());

    cJSON *inputEndpoints;
    cJSON_AddItemToObject(module, "inputEndpoints", inputEndpoints = cJSON_CreateArray());
    for(int i=0 ; i<descriptor->getInputEndpointsCount() ; i++)
        cJSON_AddItemToArray(inputEndpoints, serialize_endpoint(descriptor->getInputEndpointDescriptor(i)));

    cJSON *outputEndpoints;
    cJSON_AddItemToObject(module, "outputEndpoints", outputEndpoints = cJSON_CreateArray());
    for(int i=0 ; i<descriptor->getOutputEndpointsCount() ; i++)
        cJSON_AddItemToArray(outputEndpoints, serialize_endpoint(descriptor->getOutputEndpointDescriptor(i)));

    cJSON *connections;
    cJSON_AddItemToObject(module, "connections", connections = cJSON_CreateArray());
    for (int i = 0 ; i<descriptor->getDataStreamDescriptorCount() ; i++)
        cJSON_AddItemToArray(connections, serialize_connection(descriptor->getDataStreamDescriptor(i)));

    return module;
}

cJSON* serialize_endpoint(nuiEndpointDescriptor *descriptor)
{
    cJSON *endpoint = cJSON_CreateObject();
    cJSON_AddNumberToObject(endpoint, "index", descriptor->getIndex());
    cJSON_AddStringToObject(endpoint, "descriptor", descriptor->getDescriptor().c_str());
    return endpoint;
}

cJSON* serialize_connection(nuiDataStreamDescriptor *descriptor)
{
    cJSON *connection = cJSON_CreateObject();
    cJSON_AddNumberToObject(connection, "sourceModule",     descriptor->sourceModuleID   );
    cJSON_AddNumberToObject(connection, "sourcePort",       descriptor->sourcePort       );
    cJSON_AddNumberToObject(connection, "destinationModule",descriptor->sourceModuleID   );
    cJSON_AddNumberToObject(connection, "destinationPort",  descriptor->sourceModuleID   );

    cJSON_AddNumberToObject(connection, "buffered",         (int)(descriptor->buffered)  );
    cJSON_AddNumberToObject(connection, "bufferSize",       (int)(descriptor->bufferSize));
    cJSON_AddNumberToObject(connection, "deepCopy",         (int)(descriptor->deepCopy)  );
    cJSON_AddNumberToObject(connection, "asyncMode",        (int)(descriptor->asyncMode) );
    cJSON_AddNumberToObject(connection, "lastPacket",       (int)(descriptor->lastPacket));
    cJSON_AddNumberToObject(connection, "overflow",         (int)(descriptor->overflow)  );
    return connection;
}

//====================== LIST
void web_list_dynamic(struct evhttp_request *req, void *arg) 
{
    cJSON *root, *data;
    
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", 1);
    cJSON_AddItemToObject(root, "list", data = cJSON_CreateArray());

    std::vector<std::string> *list;
    list = nuiFrameworkManager::getInstance()->listDynamicModules();
    std::vector<std::string>::iterator it;
    for (it = list->begin() ; it!= list->end() ; it++)
        cJSON_AddItemToArray(data, cJSON_CreateString(it->c_str()));

    web_json(req, root);
}

void web_list_pipelines(struct evhttp_request *req, void *arg) 
{
    cJSON *root, *data;

    std::string hosterName;
    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "hostername") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: hostername");
    }
    
    hosterName = evhttp_find_header(&headers, "hostername");

    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", 1);
    cJSON_AddItemToObject(root, "list", data = cJSON_CreateArray());

    std::vector<std::string> *list;
    list = nuiFrameworkManager::getInstance()->listPipelines(hosterName);
    std::vector<std::string>::iterator it;
    for (it = list->begin() ; it!= list->end() ; it++)
        cJSON_AddItemToArray(data, cJSON_CreateString(it->c_str()));

    web_json(req, root);
}

//====================== WORKFLOW
void web_workflow_start(struct evhttp_request *req, void *arg) 
{
    cJSON *root;
    nuiFrameworkManager::getInstance()->workflowStart();
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", 1);
    web_json(req, root);
}

void web_workflow_stop(struct evhttp_request *req, void *arg) 
{
    cJSON *root;
    nuiFrameworkManager::getInstance()->workflowStop();
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", 1);
    web_json(req, root);
}

void web_workflow_quit(struct evhttp_request *req, void *arg) 
{
    cJSON *root;
    nuiFrameworkManager::getInstance()->workflowQuit();
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", 1);
    web_json(req, root);
    SLEEP(1000);
    want_quit = true;
}

//====================== CREATE
void web_create_pipeline(struct evhttp_request *req, void *arg) 
{
    std::string pipeline;
    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    pipeline = evhttp_find_header(&headers, "pipeline");
    if(pipeline.empty())
        return web_error(req, "incorrect argument: pipeline");

    nuiModuleDescriptor* descriptor = nuiFrameworkManager::getInstance()->createPipeline(pipeline);

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_pipeline(descriptor));

    web_json(req, root);
}

void web_create_module(struct evhttp_request *req, void *arg) 
{
    std::string pipeline, module;
    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    if ( evhttp_find_header(&headers, "module") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: module");
    }
    pipeline = evhttp_find_header(&headers, "pipeline");
    if(pipeline.empty())
        return web_error(req, "incorrect argument: pipeline");
    module = evhttp_find_header(&headers, "module");
    if(module.empty())
        return web_error(req, "incorrect argument: module");

    nuiModuleDescriptor *descriptor = nuiFrameworkManager::getInstance()->createModule(pipeline,module);

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_pipeline(descriptor));
    web_json(req, root);
}

void web_create_connection(struct evhttp_request *req, void *arg) 
{
    std::string pipeline;
    int srcIndex, srcPort;
    int destIndex, destPort;

    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    if ( evhttp_find_header(&headers, "source") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: source");
    }
    if ( evhttp_find_header(&headers, "sourcePort") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: sourcePort");
    }    
    if ( evhttp_find_header(&headers, "destination") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: destination");
    }
    if ( evhttp_find_header(&headers, "destinationPort") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: destinationPort");
    }
    pipeline = evhttp_find_header(&headers, "pipeline");
    srcIndex = _atoi(evhttp_find_header(&headers, "source"));
    destIndex = _atoi(evhttp_find_header(&headers, "destination"));
    srcPort = _atoi(evhttp_find_header(&headers, "sourcePort"));
    destPort = _atoi(evhttp_find_header(&headers, "destinationPort"));
    
    nuiDataStreamDescriptor* descriptor = nuiFrameworkManager::getInstance()->
        createConnection(pipeline,srcIndex,destIndex,srcPort,destPort);

    cJSON *root;
    root = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_connection(descriptor));

    web_json(req, root);
}

//====================== UPDATE
void web_update_pipeline(struct evhttp_request *req, void *arg) 
{
    std::string pipeline; 
    std::string *newName = new std::string;
    std::string *newDescription = new std::string; 
    std::string *newAuthor = new std::string; 

    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    pipeline = evhttp_find_header(&headers, "pipeline");

    if ( evhttp_find_header(&headers, "description") != NULL ) 
        *newDescription = evhttp_find_header(&headers, "description");
    if ( evhttp_find_header(&headers, "name") != NULL ) 
        *newName = evhttp_find_header(&headers, "name");
    if ( evhttp_find_header(&headers, "author") != NULL ) 
        *newAuthor = evhttp_find_header(&headers, "author");
    
    nuiModuleDescriptor* descr = nuiFrameworkManager::getInstance()->getPipeline(pipeline);
    if(descr == NULL)
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "pipeline not found");
    }
    if(!newAuthor->empty())
        descr->setAuthor(*newAuthor);
    else
        return web_error(req, "incorrect argument: author");
    if(!newDescription->empty())
        descr->setDescription(*newDescription);
    else
        return web_error(req, "incorrect argument: description");
    if(!newName->empty())
        descr->setName(*newName);
    else
        return web_error(req, "incorrect argument: name");

    nuiModuleDescriptor* descriptor = 
        nuiFrameworkManager::getInstance()->updatePipeline(pipeline, descr);

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", 1);
    cJSON_AddItemToObject(root,"descriptor",serialize_pipeline(descriptor));

    web_json(req, root);
}

void web_update_pipelineProperty(struct evhttp_request *req, void *arg) 
{
    std::string pipeline, *key = new std::string, *value = new std::string, 
        *description = new std::string;

    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    if ( evhttp_find_header(&headers, "key") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: key");
    }
    if ( evhttp_find_header(&headers, "value") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: value");
    }
    if ( evhttp_find_header(&headers, "description") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: description");
    }

    pipeline = evhttp_find_header(&headers, "pipeline");
    *key = evhttp_find_header(&headers, "key");
    *value = evhttp_find_header(&headers, "value");
    *description = evhttp_find_header(&headers, "description");

    nuiModuleDescriptor* descr = nuiFrameworkManager::getInstance()->getPipeline(pipeline);
    if (descr == NULL)
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "pipeline not found");
    }

    std::map<std::string, nuiProperty*> props = descr->getProperties();
    std::map<std::string, nuiProperty*>::iterator property = props.find(*key);
    property->second->set(*value);
    property->second->setDescription(*description);

    nuiModuleDescriptor* descriptor = 
        nuiFrameworkManager::getInstance()->updatePipeline(pipeline, descr);

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_pipeline(descriptor));

    web_json(req, root);
}

void web_update_moduleProperty(struct evhttp_request *req, void *arg) 
{
    std::string pipeline, *key = new std::string, *value = new std::string, 
        *description = new std::string;
    int moduleIndex;

    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    if ( evhttp_find_header(&headers, "module") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: module");
    }
    if ( evhttp_find_header(&headers, "key") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: key");
    }
    if ( evhttp_find_header(&headers, "value") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: value");
    }
    if ( evhttp_find_header(&headers, "description") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: description");
    }

    pipeline = evhttp_find_header(&headers, "pipeline");
    moduleIndex = _atoi(evhttp_find_header(&headers, "module"));
    if(moduleIndex < 0)
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "incorrect argument: module");
    }
    *key = evhttp_find_header(&headers, "key");
    *value = evhttp_find_header(&headers, "value");
    *description = evhttp_find_header(&headers, "description");

    nuiModuleDescriptor* descr = nuiFrameworkManager::getInstance()->getModule(pipeline, moduleIndex);
    if (descr == NULL)
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "module not found");
    }

    std::map<std::string, nuiProperty*> props = descr->getProperties();
    std::map<std::string, nuiProperty*>::iterator property = props.find(*key);
    property->second->set(*value);
    property->second->setDescription(*description);
    
    nuiModuleDescriptor* descriptor = 
        nuiFrameworkManager::getInstance()->updateModule(pipeline,moduleIndex, descr);

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_pipeline(descriptor));

    web_json(req, root);
}

void web_update_endpoint(struct evhttp_request *req, void *arg) 
{
    std::string pipeline, type, *typeDescriptor = new std::string;
    int index, newIndex;

    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);

    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    if ( evhttp_find_header(&headers, "type") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: type");
    }
    pipeline = evhttp_find_header(&headers, "pipeline");
    type = evhttp_find_header(&headers, "type");
    index = _atoi(evhttp_find_header(&headers, "index"));
    if(index < 0)
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "incorrect argument: index");
    }

    if(evhttp_find_header(&headers, "newDescriptor") != NULL)
    {
        *typeDescriptor = evhttp_find_header(&headers, "newDescriptor");
        if(typeDescriptor->empty())
        {
            evhttp_clear_headers(&headers);
            return web_error(req, "incorrect argument: newDescriptor");
        }
    }
    if(evhttp_find_header(&headers, "newIndex") != NULL)
    {
        newIndex = _atoi(evhttp_find_header(&headers, "newIndex"));
        if(newIndex < 0)
        {
            evhttp_clear_headers(&headers);
            return web_error(req, "incorrect argument: newIndex");
        }
    }

    nuiEndpointDescriptor* current;
    nuiEndpointDescriptor* descriptor;
    if(type == "input")
    {
        current = nuiFrameworkManager::getInstance()->getInputEndpoint(pipeline,index);
        if(current == NULL)
        {
            evhttp_clear_headers(&headers);
            return web_error(req, "incorrect argument: index");
        }
        current->setDescriptor(*typeDescriptor);
        current->setIndex(newIndex);
        descriptor = nuiFrameworkManager::getInstance()->updateInputEndpoint(pipeline, index, current);
    }
    else if(type == "output")
    {
        current = nuiFrameworkManager::getInstance()->getOutputEndpoint(pipeline,index);
        if(current == NULL)
        {
            evhttp_clear_headers(&headers);
            return web_error(req, "incorrect argument: index");
        }
        current->setDescriptor(*typeDescriptor);
        current->setIndex(newIndex);
        descriptor = nuiFrameworkManager::getInstance()->updateOutputEndpoint(pipeline, index, current);
    }
    else
    {
        return web_error(req, "incorrect argument: type");
    }

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_endpoint(descriptor));

    web_json(req, root);
}

void web_update_endpointCount(struct evhttp_request *req, void *arg) 
{
    std::string *pipeline = new std::string(), *type = new std::string();
    int newCount;

    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);

    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    if ( evhttp_find_header(&headers, "type") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: type");
    }
    if ( evhttp_find_header(&headers, "count") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: count");
    }
    *pipeline = evhttp_find_header(&headers, "pipeline");
    *type = evhttp_find_header(&headers, "type");
    newCount = _atoi(evhttp_find_header(&headers, "count"));
    if(newCount < 0)
        return web_error(req, "incorrect argument: count");

    nuiModuleDescriptor* current;
    int countUpdated = 0;
    if(*type == "input")
    {
        current = nuiFrameworkManager::getInstance()->getPipeline(*pipeline);
        if(current == NULL)
            return web_error(req, "incorrect argument: pipeline");
        countUpdated =nuiFrameworkManager::getInstance()->setInputEndpointCount(*pipeline, newCount);
    }
    else if(*type == "output")
    {
        current = nuiFrameworkManager::getInstance()->getPipeline(*pipeline);
        if(current == NULL)
            return web_error(req, "incorrect argument: pipeline");
        countUpdated =nuiFrameworkManager::getInstance()->setOutputEndpointCount(*pipeline, newCount);
    }
    else
    {
        return web_error(req, "incorrect argument: type");
    }

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", 1);
    cJSON_AddNumberToObject(root,"count",countUpdated);

    web_json(req, root);
}

void web_update_connection(struct evhttp_request *req, void *arg) 
{
    std::string pipeline;
    int srcIndex, srcPort;
    int destIndex, destPort;

    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }
    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    pipeline = evhttp_find_header(&headers, "pipeline");

    if ( evhttp_find_header(&headers, "source") == NULL ){
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: source");
    }
    if ( evhttp_find_header(&headers, "sourcePort") == NULL ){
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: sourcePort");
    }
    if ( evhttp_find_header(&headers, "destination") == NULL ){
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: destination");
    }
    if ( evhttp_find_header(&headers, "destinationPort") == NULL){
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: destinationPort");
    }
    srcIndex  = _atoi(evhttp_find_header(&headers, "source"));
    srcPort   = _atoi(evhttp_find_header(&headers, "sourcePort"));
    destIndex = _atoi(evhttp_find_header(&headers, "destination"));
    destPort  = _atoi(evhttp_find_header(&headers, "destinationPort"));
    if(srcIndex < 0 || srcPort < 0 || destIndex < 0 || destPort < 0)
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "incorrect connection");
    }

    nuiDataStreamDescriptor *current = nuiFrameworkManager::getInstance()->
        getConnection(pipeline, srcIndex,destIndex,srcPort,destPort);
    if(current == NULL)
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "connection not found");
    }
    
    int tmp = _atoi(evhttp_find_header(&headers, "deepCopy"));
    if(tmp == 0)
        current->deepCopy = false;
    else if (tmp == 1)
        current->deepCopy = true;
    tmp = _atoi(evhttp_find_header(&headers, "asyncMode"));
    if(tmp == 0)
        current->asyncMode = false;
    else if (tmp == 1)
        current->asyncMode = true;
    tmp = _atoi(evhttp_find_header(&headers, "buffered"));
    if(tmp == 0)
        current->buffered = false;
    else if (tmp == 1)
        current->buffered = true;
    tmp = _atoi(evhttp_find_header(&headers, "bufferSize"));
    if(tmp < 0)
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "incorrect argument: bufferSize");
    }
    else current->bufferSize = tmp;
    tmp = _atoi(evhttp_find_header(&headers, "lastPacket"));
    if(tmp == 0)
        current->lastPacket = false;
    else if (tmp == 1)
        current->lastPacket = true;
    tmp = _atoi(evhttp_find_header(&headers, "overflow"));
    if(tmp == 0)
        current->overflow = false;
    else if (tmp == 1)
        current->overflow = true;

    nuiDataStreamDescriptor *descriptor = nuiFrameworkManager::getInstance()->
        updateConnection(pipeline,srcIndex,destIndex,srcPort,destPort,current); 

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if( descriptor!= NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_connection(descriptor));

    web_json(req, root);
}

//====================== DELETE
void web_delete_pipeline(struct evhttp_request *req, void *arg) 
{
    std::string pipeline, newName, newDescription;
    bool nameChange = true;

    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    /*if ( evhttp_find_header(&headers, "description") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: description");
    }*/
    if ( evhttp_find_header(&headers, "name") == NULL ) 
        nameChange = false;
    pipeline = evhttp_find_header(&headers, "pipeline");
    newDescription = evhttp_find_header(&headers, "description");
    if(nameChange)
        newName = evhttp_find_header(&headers, "name");

    nuiFrameworkManagerErrorCode error = 
        nuiFrameworkManager::getInstance()->deletePipeline(pipeline);

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", 1);

    web_json(req, root);
}

void web_delete_module(struct evhttp_request *req, void *arg) 
{
    std::string pipeline;
    int index;

    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    if ( evhttp_find_header(&headers, "moduleId") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: moduleId");
    }
    pipeline = evhttp_find_header(&headers, "pipeline");
    index = _atoi(evhttp_find_header(&headers, "moduleId"));
    if(index < 0)
        return web_error(req, "incorrect argument: moduleId");

    nuiModuleDescriptor* descriptor = 
        nuiFrameworkManager::getInstance()->deleteModule(pipeline, index);
    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_pipeline(descriptor));

    web_json(req, root);
}

void web_delete_endpoint(struct evhttp_request *req, void *arg) 
{
    std::string pipeline, type;
    int index;

    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    if ( evhttp_find_header(&headers, "type") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: type");
    }
    if ( evhttp_find_header(&headers, "index") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: index");
    }

    pipeline = evhttp_find_header(&headers, "pipeline");
    index = _atoi(evhttp_find_header(&headers, "index"));
    if(index < 0)
        return web_error(req, "incorrect argument: index");
    type = evhttp_find_header(&headers, "type");

    nuiModuleDescriptor* descriptor;
    if(type == "input")
    {
        descriptor = nuiFrameworkManager::getInstance()->deleteInputEndpoint(pipeline,index);
    }
    else if(type == "output")
    {
        descriptor = nuiFrameworkManager::getInstance()->deleteOutputEndpoint(pipeline,index);
    }
    else
    {
        return web_error(req, "incorrect argument: type");
    }

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_module(descriptor));

    web_json(req, root);
}

void web_delete_connection(struct evhttp_request *req, void *arg) 
{
    std::string pipeline;
    int srcIndex, srcPort;
    int destIndex, destPort;

    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }
    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    pipeline = evhttp_find_header(&headers, "pipeline");

    if ( evhttp_find_header(&headers, "source") == NULL ){
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: source");
    }
    if ( evhttp_find_header(&headers, "sourcePort") == NULL ){
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: sourcePort");
    }
    if ( evhttp_find_header(&headers, "destination") == NULL ){
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: destination");
    }
    if ( evhttp_find_header(&headers, "destinationPort") == NULL){
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: destinationPort");
    }
    srcIndex  = _atoi(evhttp_find_header(&headers, "source"));
    srcPort   = _atoi(evhttp_find_header(&headers, "sourcePort"));
    destIndex = _atoi(evhttp_find_header(&headers, "destination"));
    destPort  = _atoi(evhttp_find_header(&headers, "destinationPort"));
    if(srcIndex < 0 || srcPort < 0 || destIndex < 0 || destPort < 0)
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "incorrect connection");
    }

    nuiModuleDescriptor* descriptor = nuiFrameworkManager::getInstance()->
        deleteConnection(pipeline,srcIndex,destIndex,srcPort,destPort);

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_pipeline(descriptor));

    web_json(req, root);
}

//====================== GET
void web_get_current(struct evhttp_request *req, void *arg) 
{
    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    nuiModuleDescriptor* descriptor = nuiFrameworkManager::getInstance()->getCurrentPipeline();
    if(descriptor == NULL)
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "pipeline not found");
    }

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_pipeline(descriptor));

    web_json(req, root);
}

void web_get_pipeline(struct evhttp_request *req, void *arg) 
{
    std::string pipeline;
    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    pipeline = evhttp_find_header(&headers, "pipeline");

    nuiModuleDescriptor* descriptor = nuiFrameworkManager::getInstance()->getPipeline(pipeline);
    if(descriptor == NULL)
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "pipeline not found");
    }

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_pipeline(descriptor));

    web_json(req, root);
}

void web_get_module(struct evhttp_request *req, void *arg) 
{
    std::string pipeline;
    int index;
    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    if ( evhttp_find_header(&headers, "index") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: index");
    }
    pipeline = evhttp_find_header(&headers, "pipeline");
    index = _atoi(evhttp_find_header(&headers, "index"));
    if(index < 0)
        return web_error(req, "incorrect argument: index");

    nuiModuleDescriptor* descriptor = nuiFrameworkManager::getInstance()->getModule(pipeline, index);
    if(descriptor == NULL)
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "module not found");
    }

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_module(descriptor));

    web_json(req, root);
}

void web_get_connection(struct evhttp_request *req, void *arg) 
{
    std::string pipeline;
    int srcIndex, srcPort;
    int destIndex, destPort;

    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }
    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    pipeline = evhttp_find_header(&headers, "pipeline");

    if ( evhttp_find_header(&headers, "source") == NULL ){
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: source");
    }
    if ( evhttp_find_header(&headers, "sourcePort") == NULL ){
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: sourcePort");
    }
    if ( evhttp_find_header(&headers, "destination") == NULL ){
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: destination");
    }
    if ( evhttp_find_header(&headers, "destinationPort") == NULL){
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: destinationPort");
    }
    srcIndex  = _atoi(evhttp_find_header(&headers, "source"));
    srcPort   = _atoi(evhttp_find_header(&headers, "sourcePort"));
    destIndex = _atoi(evhttp_find_header(&headers, "destination"));
    destPort  = _atoi(evhttp_find_header(&headers, "destinationPort"));
    if(srcIndex < 0 || srcPort < 0 || destIndex < 0 || destPort < 0)
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "incorrect connection");
    }

    nuiDataStreamDescriptor* descriptor = nuiFrameworkManager::getInstance()->
        getConnection(pipeline, srcIndex,destIndex,srcPort,destPort);
    if(descriptor == NULL)
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "connection not found");
    }

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_connection(descriptor));

    web_json(req, root);
}

//NAVIGATE
void web_navigate_push(struct evhttp_request *req, void *arg) 
{
    int index;
    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "index") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: index");
    }
    index = _atoi(evhttp_find_header(&headers, "index"));
    if(index < 0)
        return web_error(req, "incorrect argument: index");

    nuiModuleDescriptor* descriptor = nuiFrameworkManager::getInstance()->navigatePush(index);

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_pipeline(descriptor));

    web_json(req, root);
}


void web_navigate_pop(struct evhttp_request *req, void *arg) 
{
    struct evkeyvalq headers;
    const char *uri;

    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }

    evhttp_parse_query(uri, &headers);

    nuiModuleDescriptor* descriptor = nuiFrameworkManager::getInstance()->navigatePop();

    cJSON *root;
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "success", (descriptor == NULL) ? 0 : 1);
    if(descriptor != NULL)
        cJSON_AddItemToObject(root,"descriptor",serialize_pipeline(descriptor));

    web_json(req, root);
}

//SAVE
void web_save_pipeline(struct evhttp_request *req, void *arg) {
    struct evbuffer *evb = evbuffer_new();
    
    std::string pipeline;
    std::string fileName;

    struct evkeyvalq headers;
    const char *uri;
    uri = evhttp_request_uri(req);
    if ( uri == NULL ) {
        evhttp_clear_headers(&headers);
        return web_error(req, "unable to retreive uri");
    }
    evhttp_parse_query(uri, &headers);
    if ( evhttp_find_header(&headers, "pipeline") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: pipeline");
    }
    if ( evhttp_find_header(&headers, "file") == NULL ) 
    {
        evhttp_clear_headers(&headers);
        return web_error(req, "missing argument: file");
    }
    pipeline = evhttp_find_header(&headers, "pipeline");
    fileName = evhttp_find_header(&headers, "file");

	nuiFrameworkManager::getInstance()->saveSettingsAsXml(fileName.c_str(), pipeline);
	std::string serizalized = "YES";

    evhttp_parse_query(uri, &headers);

    if ( evhttp_find_header(&headers, "download") != NULL ) 
    {
        evhttp_add_header(req->output_headers, "Content-Type", "application/force-download; name=\"settings.xml\"");
        evhttp_add_header(req->output_headers, "Content-Disposition", "attachment; filename=\"settings.xml\"");
    } else
        evhttp_add_header(req->output_headers, "Content-Type", "text/plain");

    evbuffer_add(evb, serizalized.c_str(), strlen(serizalized.c_str()));
    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);

    evhttp_clear_headers(&headers);
}

/*
void web_utterance_begin(struct evhttp_request *req, void *arg) {
    LOG(CCX_INFO, "Utterance started! ");
    web_message(req, "utterance start ok");
    pipeline->clearStreams();
}

void web_utterance_speech_begin(struct evhttp_request *req, void *arg) {
    // send a property container that controls recording; these property changes are properly notified for threaded operation.
    web_message(req, "speech begin ok");
    ccxModule* triggerModule = pipeline->getModuleById("Audio");
    LOG(CCX_DEBUG, "on: " << triggerModule->getName());
    // do a notifyUpdate() on the audio module, no need for input data as this is a trigger
    ccxDataGenericContainer* triggerContainer = new ccxDataGenericContainer();
    triggerContainer->properties["recording"] = new ccxProperty(true);
    triggerModule->getInput()->push(triggerContainer);
    triggerModule->trigger();
}

void web_utterance_speech_end(struct evhttp_request *req, void *arg) {
    // same as above, property container
    web_message(req, "speech end ok");
    ccxModule* triggerModule = pipeline->getModuleById("Audio");
    LOG(CCX_DEBUG, "off: " << triggerModule->getName());
    ccxDataGenericContainer* triggerContainer = new ccxDataGenericContainer();
    triggerModule->getInput()->push(triggerContainer);
    triggerModule->trigger();
}

void web_utterance_gesture_data(struct evhttp_request *req, void *arg) {
    // instead of a property container we feed JSON, (but for now just trigger())
    LOG(CCX_DEBUG, "Gesture data added to the utterance...");
    struct evbuffer* buf = req->input_buffer;
    char* input = (char *)malloc(sizeof(char) * 16384);
    evbuffer_remove(buf, input, 16384);
    cJSON *parsedInput = cJSON_Parse(input);
    LOG(CCX_DEBUG, input);
    std::vector<client::unimodalLeafNode> *gestureTree = new std::vector<client::unimodalLeafNode>();
    for(int index = 0; index < cJSON_GetArraySize(parsedInput); index++) {
        cJSON *item = cJSON_GetArrayItem(parsedInput, index);
        std::string typeString = std::string(cJSON_PrintUnformatted(cJSON_GetObjectItem(item, "type")));
        std::string valString = std::string(cJSON_PrintUnformatted(cJSON_GetObjectItem(item, "val")));
        typeString.erase(
                         remove( typeString.begin(), typeString.end(), '\"' ),
                         typeString.end()
                         );
        valString.erase(
                        remove( valString.begin(), valString.end(), '\"' ),
                        valString.end()
                        );
        client::unimodalLeafNode *debugNode = new client::unimodalLeafNode;
        debugNode->type = typeString;
        debugNode->val = valString;
        gestureTree->push_back(*debugNode);

    }
    // do a notifyUpdate() on the gesture JSON module, and feed in the special gesture stream (pushing to the stream would have it call this automatically)
    web_message(req, "utterance data ok");
    ccxModule* triggerModule = pipeline->getModuleById("Gesture");
    LOG(CCX_DEBUG, "gd: " << triggerModule->getName());
    triggerModule->getInput()->push(gestureTree);
    triggerModule->trigger();
}

void web_utterance_end(struct evhttp_request *req, void *arg) {
    LOG(CCX_INFO, "Utterance stop!");
    web_message(req, "Utterance stop.");
}

void web_utterance_get(struct evhttp_request *req, void *arg) {
    LOG(CCX_INFO, "Utterance get!");
    cJSON* outputJSON = (cJSON *)pipeline->getModuleById("Interaction")->getOutput()->getData();
    if(outputJSON != NULL) web_json(req, outputJSON);
    else web_error(req, "no valid utterance");
}
*/

typedef nuiTree<int,nuiModuleDescriptor> moduleDescriptorTree;
typedef nuiTreeNode<int, nuiModuleDescriptor> moduleDescriptorNode;

int main(int argc, char **argv) 
{
	nuiTreeNode<int, int>* node = new nuiTreeNode<int, int>(0,0);
	node->addChildNode(new nuiTreeNode<int, int>(1,1));
	node->addChildNode(new nuiTreeNode<int, int>(2,2));
	node->addChildNode(new nuiTreeNode<int, int>(3,3));
	node->getChild(1)->addChildNode(new nuiTreeNode<int, int>(4,4));
	node->getChild(1)->addChildNode(new nuiTreeNode<int, int>(5,5));
	node->getChild(3)->addChildNode(new nuiTreeNode<int, int>(6,6));
	node->getChild(3)->addChildNode(new nuiTreeNode<int, int>(7,7));
	nuiTree<int,int>* tree = new nuiTree<int,int>(node);

	for (nuiTree<int,int>::iterator iter = tree->begin();iter!=tree->end();iter++)
	{
		printf("%i ", (*(iter))->getKey());
	}

	
	int exit_ret = 0;

	// initialize all signals
#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
	signal(SIGTERM, signal_term);
	signal(SIGINT, signal_term);

	// initialize log
	nuiDebugLogger::init(config_syslog);

	// initialize daemon (network...)
	nuiDaemon::init();
	
	nuiFrameworkManager::getInstance()->loadAddonsAtPath("addons");
	nuiFrameworkManager::getInstance()->initializeFrameworkManager("configs/presets/test.xml");
//	nuiFrameworkManager::getInstance()->initializeFrameworkManager("configs/presets/module_settings.xml");
	nuiFrameworkManager::getInstance()->workflowStart();

	nuiJsonRpcApi::getInstance()->init("127.0.0.1", 7500);
	
	base = event_init();

	server = evhttp_new(NULL);
	if ( server == NULL ) 
    {
		LOG(NUI_CRITICAL, "unable to create http server");
		goto exit_critical;
	}


    int ret = evhttp_bind_socket(server, "127.0.0.1", 7500);
	if ( ret == -1 ) 
    {
		perror("HTTP server");
		LOG(NUI_ERROR, "unable to open socket for 127.0.0.1:7500");

        goto exit_critical;
    }
    else
	    LOG(NUI_INFO, "Http server running at http://127.0.0.1:7500/");
   
    //SET EVENTS
    evhttp_set_cb(server, "/", web_index, NULL);

    //LIST
    evhttp_set_cb(server, "/list/dynamic", web_list_dynamic, NULL);
    evhttp_set_cb(server, "/list/pipelines", web_list_pipelines, NULL);
    //WORKFLOW
    evhttp_set_cb(server, "/workflow/start", web_workflow_start, NULL);
    evhttp_set_cb(server, "/workflow/stop", web_workflow_stop, NULL);
    evhttp_set_cb(server, "/workflow/quit", web_workflow_quit, NULL);
    //CREATE
    evhttp_set_cb(server, "/create/pipeline", web_create_pipeline, NULL);
    evhttp_set_cb(server, "/create/module", web_create_module, NULL);
    evhttp_set_cb(server, "/create/connection", web_create_connection, NULL);
    //UPDATE
    evhttp_set_cb(server, "/update/pipeline", web_update_pipeline, NULL);
    evhttp_set_cb(server, "/update/pipelineProperty", web_update_pipelineProperty, NULL);
    evhttp_set_cb(server, "/update/moduleProperty", web_update_moduleProperty, NULL);
    evhttp_set_cb(server, "/update/endpoint", web_update_endpoint, NULL);
    evhttp_set_cb(server, "/update/connection", web_update_connection, NULL);
    evhttp_set_cb(server, "/update/endpointCount", web_update_endpointCount, NULL);
    //DELETE
    evhttp_set_cb(server, "/delete/pipeline", web_delete_pipeline, NULL);
    evhttp_set_cb(server, "/delete/module", web_delete_module, NULL);
    evhttp_set_cb(server, "/delete/endpoint", web_delete_endpoint, NULL);
    evhttp_set_cb(server, "/delete/connection", web_delete_connection, NULL);
    //GET
    evhttp_set_cb(server, "/get/current", web_get_current, NULL);
    evhttp_set_cb(server, "/get/pipeline", web_get_pipeline, NULL);
    evhttp_set_cb(server, "/get/module", web_get_module, NULL);
    evhttp_set_cb(server, "/get/connection", web_get_connection, NULL);
    //NAVIGATE
    evhttp_set_cb(server, "/navigate/push", web_navigate_push, NULL);
    evhttp_set_cb(server, "/navigate/pop", web_navigate_pop, NULL);
    //SAVE
    evhttp_set_cb(server, "/save/pipeline", web_save_pipeline, NULL);

	//TEMP INTERACTION FOR TESTING
	/*
	evhttp_set_cb(server, "/utterance/begin", web_utterance_begin, NULL);
    evhttp_set_cb(server, "/utterance/end", web_utterance_end, NULL);
    evhttp_set_cb(server, "/utterance/speech/begin", web_utterance_speech_begin, NULL);
    evhttp_set_cb(server, "/utterance/speech/end", web_utterance_speech_end, NULL);
    evhttp_set_cb(server, "/utterance/gesture/data", web_utterance_gesture_data, NULL);
    evhttp_set_cb(server, "/utterance/get", web_utterance_get, NULL);
	*/

 	evhttp_set_gencb(server, web_file, NULL);

	// main loop
	do
    {
		// if we're running the server, allow the event loop to have control for a while
		if ( server != NULL )
			event_base_loop(base, EVLOOP_ONCE|EVLOOP_NONBLOCK);
        SLEEP(g_config_delay);
    } while ( want_quit == false );
	nuiFrameworkManager::getInstance()->workflowStop();
	nuiFrameworkManager::getInstance()->workflowQuit();

exit_standard:
	if ( server != NULL )
		evhttp_free(server);
	if ( base != NULL )
		event_base_free(base);
	return 0;

exit_critical:
	exit_ret = 1;
	goto exit_standard;
}