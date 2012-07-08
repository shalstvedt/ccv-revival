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
static nuiJsonRpcApi *server = NULL;
static evhttp *httpserver;
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
	nuiFrameworkManager::getInstance()->workflowStart();

	nuiJsonRpcApi::getInstance()->init("127.0.0.1", 7500);
	
	base = event_init();

	server = nuiJsonRpcApi::getInstance();

	httpserver = evhttp_new(NULL);
	
	if ( httpserver == NULL ) 
    {
		LOG(NUI_CRITICAL, "unable to create http server");
		goto exit_critical;
	}


    int ret = evhttp_bind_socket(httpserver, "127.0.0.1", 7501);
	if ( ret == -1 ) 
    {
		perror("HTTP server");
		LOG(NUI_ERROR, "unable to open socket for 127.0.0.1:7501");

        goto exit_critical;
    }
    else
	    LOG(NUI_INFO, "Http server running at http://127.0.0.1:7501/");
   
    //SET EVENTS
    evhttp_set_cb(httpserver, "/", web_index, NULL);
 	evhttp_set_gencb(httpserver, web_file, NULL);


	server->startApi();

do
    {
		// if we're running the server, allow the event loop to have control for a while
		if ( server != NULL )
			event_base_loop(base, EVLOOP_ONCE|EVLOOP_NONBLOCK);
			SLEEP(g_config_delay);
	} while ( server->isFinished() == false );

	nuiFrameworkManager::getInstance()->workflowStop();
	nuiFrameworkManager::getInstance()->workflowQuit();

exit_standard:
	if ( server != NULL )

	//	evhttp_free(server);
	if ( base != NULL )
		event_base_free(base);
	return exit_ret;

exit_critical:
	exit_ret = 1;
	goto exit_standard;
}