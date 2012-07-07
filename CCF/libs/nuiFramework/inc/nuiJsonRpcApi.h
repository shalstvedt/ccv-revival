#include "boost/cstdint.hpp"
#include "pasync.h"

#include "json/json.h"
#include "networking.h"
#include "jsonrpc.h"
#include "jsonrpc_tcpserver.h"

#include "nuiModule.h"
#include "nuiDataStream.h"
#include "nuiEndpoint.h"

inline bool str_is_zero(const char* pStr);

//! returns 0 - MAX_INT integer in case of success, -1 in case of failure
//! had to write own implementation because std atoi converts in 1..MAX_INT 
//! range
inline int _atoi(const char* pStr);

//! TODO : optional arguments methods
class nuiJsonRpcApi : public pt::thread
{
public:
	static nuiJsonRpcApi *getInstance();
	bool init(std::string address, int port);
	void startApi();
	bool isInitialized();
	bool isFinished();
protected:
private:
	bool finished;
	bool want_quit;

	void setFailure(Json::Value &responce);
	void setSuccess(Json::Value &responce);

	nuiJsonRpcApi();
	Json::Rpc::TcpServer *server;
	void execute();
	void cleanup();

	Json::Value serialize_pipeline(nuiModuleDescriptor* descriptor);
	Json::Value serialize_module(nuiModuleDescriptor* descriptor);
	Json::Value serialize_endpoint(nuiEndpointDescriptor *descriptor);
	Json::Value serialize_connection(nuiDataStreamDescriptor *descriptor);

	bool web_list_dynamic(const Json::Value& root, Json::Value& response);
	bool web_list_pipelines(const Json::Value& root, Json::Value& response);
	bool web_workflow_start(const Json::Value& root, Json::Value& response);
	bool web_workflow_stop(const Json::Value& root, Json::Value& response);
	bool web_workflow_quit(const Json::Value& root, Json::Value& response);
	bool web_create_pipeline(const Json::Value& root, Json::Value& response);
	bool web_create_module(const Json::Value& root, Json::Value& response);
	bool web_create_connection(const Json::Value& root, Json::Value& response);
	bool web_update_pipeline(const Json::Value& root, Json::Value& response);
	bool web_update_pipelineProperty(const Json::Value& root, Json::Value& response);
	bool web_update_moduleProperty(const Json::Value& root, Json::Value& response);
	bool web_update_endpoint(const Json::Value& root, Json::Value& response);
	bool web_update_connection(const Json::Value& root, Json::Value& response);
	bool web_update_endpointCount(const Json::Value& root, Json::Value& response);
	bool web_delete_pipeline(const Json::Value& root, Json::Value& response);
	bool web_delete_module(const Json::Value& root, Json::Value& response);
	bool web_delete_endpoint(const Json::Value& root, Json::Value& response);
	bool web_delete_connection(const Json::Value& root, Json::Value& response);
	bool web_get_current(const Json::Value& root, Json::Value& response);
	bool web_get_pipeline(const Json::Value& root, Json::Value& response);
	bool web_get_module(const Json::Value& root, Json::Value& response);
	bool web_get_connection(const Json::Value& root, Json::Value& response);
	bool web_navigate_push(const Json::Value& root, Json::Value& response);
	bool web_navigate_pop(const Json::Value& root, Json::Value& response);
	bool web_save_pipeline(const Json::Value& root, Json::Value& response);
};

inline int _atoi(const char* pStr)
{
	int res = atoi(pStr);

	if ( !str_is_zero(pStr) && (res==0) )
		return -1;
	else
		return res;
};