#include "nuiJsonRpcApi.h"
#include "nuiFrameworkManager.h"

nuiJsonRpcApi *nuiJsonRpcApi::getInstance()
{
	static nuiJsonRpcApi *instance = NULL;
	if(instance == NULL)
		instance = new nuiJsonRpcApi();
	return instance;
};

bool nuiJsonRpcApi::init(std::string address, int port)
{
	if(server == NULL)
		server = new Json::Rpc::TcpServer(std::string("127.0.0.1"), 7500);

	if(!server->Bind())
	{
		delete server;
		return false;
	}
	if(!server->Listen())
	{
		delete server;
		return false;
	}

	this->finished = false;

	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_list_dynamic,std::string("web_list_dynamic")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_list_pipelines,std::string("web_list_pipelines")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_workflow_start,std::string("web_workflow_start")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_workflow_stop,std::string("web_workflow_stop")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_workflow_quit,std::string("web_workflow_quit")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_create_pipeline,std::string("web_create_pipeline")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_create_module,std::string("web_create_module")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_create_connection,std::string("web_create_connection")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_update_pipeline,std::string("web_update_pipeline")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_update_pipelineProperty,std::string("web_update_pipelineProperty")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_update_moduleProperty,std::string("web_update_moduleProperty")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_update_endpoint,std::string("web_update_endpoint")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_update_connection,std::string("web_update_connection")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_update_endpointCount,std::string("web_update_endpointCount")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_delete_pipeline,std::string("web_delete_pipeline")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_delete_module,std::string("web_delete_module")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_delete_endpoint,std::string("web_delete_endpoint")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_delete_connection,std::string("web_delete_connection")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_get_current,std::string("web_get_current")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_get_pipeline,std::string("web_get_pipeline")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_get_module,std::string("web_get_module")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_get_connection,std::string("web_get_connection")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_navigate_push,std::string("web_navigate_push")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_navigate_pop,std::string("web_navigate_pop")));
	server->AddMethod(new Json::Rpc::RpcMethod<nuiJsonRpcApi>(*this, &nuiJsonRpcApi::web_save_pipeline,std::string("web_save_pipeline")));

	return true;
};

bool nuiJsonRpcApi::isInitialized()
{
	if(server!=NULL)
		return true;
	return false;
};

void nuiJsonRpcApi::startApi()
{
	if(isInitialized())
		start();
};

void nuiJsonRpcApi::execute()
{
	while(!want_quit)
	{
		server->WaitMessage(0);	
	}
	finished = true;
}

void nuiJsonRpcApi::cleanup() { };

nuiJsonRpcApi::nuiJsonRpcApi() : pt::thread(false) 
{
	this->want_quit = false;
	this->server = NULL;
};

bool nuiJsonRpcApi::web_list_dynamic( const Json::Value& root, Json::Value& response )
{
	std::vector<std::string>* list;
	list = nuiFrameworkManager::getInstance()->listDynamicModules();

	Json::Value* jModules = new Json::Value();
	std::vector<std::string>::iterator it;
	for(it = list->begin() ; it!=list->end();it++)
		jModules->append(*it);

	setSuccess(response);
	response["list"] = *jModules;
	
	return true;
}

bool nuiJsonRpcApi::web_list_pipelines( const Json::Value& root, Json::Value& response )
{
	std::string hosterName = root["hostername"].asString();

	std::vector<std::string> *list;
	list = nuiFrameworkManager::getInstance()->listPipelines(hosterName);

	Json::Value* jModules = new Json::Value();
	std::vector<std::string>::iterator it;
	for(it = list->begin() ; it!=list->end();it++)
		jModules->append(*it);

	setSuccess(response);
	response["list"] = *jModules;
	
	return true;
}

bool nuiJsonRpcApi::web_workflow_start( const Json::Value& root, Json::Value& response )
{
	nuiFrameworkManagerErrorCode error = nuiFrameworkManager::getInstance()->workflowStart();
	if(error == NUI_FRAMEWORK_MANAGER_OK)
	{
		setSuccess(response);
		return true;
	}
	else
	{
		setFailure(response);
		return false;
	}
}

bool nuiJsonRpcApi::web_workflow_stop( const Json::Value& root, Json::Value& response )
{
	nuiFrameworkManagerErrorCode error = nuiFrameworkManager::getInstance()->workflowStop();
	if(error == NUI_FRAMEWORK_MANAGER_OK)
	{
		setSuccess(response);
		return true;
	}
	else
	{
		setFailure(response);
		return false;
	}
}

bool nuiJsonRpcApi::web_workflow_quit( const Json::Value& root, Json::Value& response )
{
	this->want_quit = true;

	setSuccess(response);

	return true;

}

bool nuiJsonRpcApi::web_create_pipeline( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString();

	nuiModuleDescriptor* descriptor = nuiFrameworkManager::getInstance()->createPipeline(pipeline);

	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_pipeline(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_create_module( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString();
	std::string module = root["module"].asString();

	nuiModuleDescriptor *descriptor = nuiFrameworkManager::getInstance()->createModule(pipeline,module);
	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_pipeline(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_create_connection( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString();	
	int srcIndex = root["source"].asInt();
	int srcPort = root["sourcePort"].asInt();
	int dstIndex = root["destination"].asInt();
	int dstPort = root["destinationPort"].asInt();

	nuiDataStreamDescriptor* descriptor = nuiFrameworkManager::getInstance()->
		createConnection(pipeline,srcIndex,dstIndex,srcPort,dstPort);

	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_connection(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_update_pipeline( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString(); 
	std::string newName = root["name"].asString();
	std::string newDescription = root["description"].asString();
	std::string newAuthor = root["author"].asString();

	nuiModuleDescriptor* descr = nuiFrameworkManager::getInstance()->getPipeline(pipeline);

	if(descr == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_pipeline(descr);
		return true;
	}
}

bool nuiJsonRpcApi::web_update_pipelineProperty( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString();
	std::string key = root["key"].asString();
	std::string value = root["value"].asString();
	std::string description = root["description"].asString();

	nuiModuleDescriptor* descr = nuiFrameworkManager::getInstance()->getPipeline(pipeline);

	std::map<std::string, nuiProperty*> props = descr->getProperties();
	std::map<std::string, nuiProperty*>::iterator property = props.find(key);
	property->second->set(value);
	property->second->setDescription(description);

	nuiModuleDescriptor* descriptor = 
		nuiFrameworkManager::getInstance()->updatePipeline(pipeline, descr);

	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_pipeline(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_update_moduleProperty( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString();
	std::string key = root["key"].asString();
	std::string value = root["value"].asString();
	std::string description = root["description"].asString();
	int moduleIndex = root["module"].asInt();

	nuiModuleDescriptor* descr = nuiFrameworkManager::getInstance()->getModule(pipeline, moduleIndex);

	std::map<std::string, nuiProperty*> props = descr->getProperties();
	std::map<std::string, nuiProperty*>::iterator property = props.find(key);
	property->second->set(value);
	property->second->setDescription(description);

	nuiModuleDescriptor* descriptor = 
		nuiFrameworkManager::getInstance()->updateModule(pipeline,moduleIndex, descr);

	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_module(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_update_endpoint( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString(); 
	std::string type = root["type"].asString();
	std::string newDescriptor = root["newDescriptor"].asString();
	int index = root["index"].asInt();
	int newIndex = root["newIndex"].asInt();

	nuiEndpointDescriptor* current = NULL;
	nuiEndpointDescriptor* descriptor = NULL;
	if(type == "input")
	{
		current = nuiFrameworkManager::getInstance()->getInputEndpoint(pipeline,index);
		if(current == NULL)
		{
			setFailure(response);
			return false;
		}
		current->setDescriptor(newDescriptor);
		current->setIndex(newIndex);
		descriptor = nuiFrameworkManager::getInstance()->updateInputEndpoint(pipeline, index, current);
	}
	else if(type == "output")
	{
		current = nuiFrameworkManager::getInstance()->getOutputEndpoint(pipeline,index);
		if(current == NULL)
		{
			setFailure(response);
			return false;
		}
		current->setDescriptor(newDescriptor);
		current->setIndex(newIndex);
		descriptor = nuiFrameworkManager::getInstance()->updateOutputEndpoint(pipeline, index, current);
	}
	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_endpoint(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_update_connection( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString(); 
	int srcIndex = root["source"].asInt(); 
	int srcPort = root["sourcePort"].asInt(); 
	int dstIndex = root["destination"].asInt(); 
	int dstPort = root["destinationPort"].asInt();

	nuiDataStreamDescriptor *current = nuiFrameworkManager::getInstance()->
		getConnection(pipeline, srcIndex,dstIndex,srcPort,dstPort);

	if(current == NULL)
	{
		setFailure(response);
		return false;
	}

	int deepCopy = response["deepCopy"].asInt();
	int asyncMode = response["asyncMode"].asInt();
	int buffered = response["buffered"].asInt();
	int bufferSize = response["bufferSize"].asInt();
	int lastPacket = response["lastPacket"].asInt();
	int overflow = response["overflow"].asInt();

	nuiDataStreamDescriptor *descriptor = nuiFrameworkManager::getInstance()->
		updateConnection(pipeline,srcIndex,dstIndex,srcPort,dstPort,current); 

	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_connection(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_update_endpointCount( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString(); 
	std::string type = root["type"].asString(); 
	int newCount = root["count"].asInt();

	nuiModuleDescriptor* current = NULL;
	int countUpdated = -1;
	if(type == "input")
	{
		current = nuiFrameworkManager::getInstance()->getPipeline(pipeline);
		if(current == NULL)
		{
			setFailure(response);
			return false;
		}
		countUpdated = nuiFrameworkManager::getInstance()->setInputEndpointCount(pipeline, newCount);
	}
	else if(type == "output")
	{
		current = nuiFrameworkManager::getInstance()->getPipeline(pipeline);
		if(current == NULL)
		{
			setFailure(response);
			return false;
		}
		countUpdated = nuiFrameworkManager::getInstance()->setOutputEndpointCount(pipeline, newCount);
	}
	if(countUpdated == -1)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["count"] = countUpdated;
		return true;
	}
}

bool nuiJsonRpcApi::web_delete_pipeline( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString();
	nuiFrameworkManagerErrorCode error = 
		nuiFrameworkManager::getInstance()->deletePipeline(pipeline);
	if(error != NUI_FRAMEWORK_MANAGER_OK)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		return true;
	}
}

bool nuiJsonRpcApi::web_delete_module( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString();
	int index = root["moduleId"].asInt();

	nuiModuleDescriptor* descriptor = 
		nuiFrameworkManager::getInstance()->deleteModule(pipeline, index);

	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_pipeline(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_delete_endpoint( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString();
	std::string type = root["type"].asString();
	int index = root["index"].asInt();

	nuiModuleDescriptor* descriptor = NULL;
	if(type == "input")
	{
		descriptor = nuiFrameworkManager::getInstance()->deleteInputEndpoint(pipeline,index);
	}
	else if(type == "output")
	{
		descriptor = nuiFrameworkManager::getInstance()->deleteOutputEndpoint(pipeline,index);
	}

	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_pipeline(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_delete_connection( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString(); 
	int srcIndex = root["source"].asInt(); 
	int srcPort = root["sourcePort"].asInt(); 
	int dstIndex = root["destination"].asInt(); 
	int dstPort = root["destinationPort"].asInt();

	nuiModuleDescriptor* descriptor = nuiFrameworkManager::getInstance()->
		deleteConnection(pipeline,srcIndex,dstIndex,srcPort,dstPort);
	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_pipeline(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_get_current( const Json::Value& root, Json::Value& response )
{
	nuiModuleDescriptor* descriptor = nuiFrameworkManager::getInstance()->getCurrentPipeline();
	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_pipeline(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_get_pipeline( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString(); 
    nuiModuleDescriptor* descriptor = nuiFrameworkManager::getInstance()->getPipeline(pipeline);
	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_pipeline(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_get_module( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString();
	int index = root["moduleId"].asInt();
	nuiModuleDescriptor* descriptor = nuiFrameworkManager::getInstance()->getModule(pipeline, index);
	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_module(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_get_connection( const Json::Value& root, Json::Value& response )
{
	std::string pipeline = root["pipeline"].asString(); 
	int srcIndex = root["source"].asInt(); 
	int srcPort = root["sourcePort"].asInt(); 
	int dstIndex = root["destination"].asInt(); 
	int dstPort = root["destinationPort"].asInt();

	nuiDataStreamDescriptor* descriptor = nuiFrameworkManager::getInstance()->
		getConnection(pipeline, srcIndex,dstIndex,srcPort,dstPort);

	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_connection(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_navigate_push( const Json::Value& root, Json::Value& response )
{
	int index = root["index"].asInt();

	nuiModuleDescriptor* descriptor = nuiFrameworkManager::getInstance()->navigatePush(index);

	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_pipeline(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_navigate_pop( const Json::Value& root, Json::Value& response )
{
	nuiModuleDescriptor* descriptor = nuiFrameworkManager::getInstance()->navigatePop();

	if(descriptor == NULL)
	{
		setFailure(response);
		return false;
	}
	else
	{
		setSuccess(response);
		response["descriptor"] = serialize_pipeline(descriptor);
		return true;
	}
}

bool nuiJsonRpcApi::web_save_pipeline( const Json::Value& root, Json::Value& response )
{
	// TODO : ? still needed ?
	return true;
}

Json::Value nuiJsonRpcApi::serialize_pipeline( nuiModuleDescriptor* descriptor )
{
	Json::Value jPipeline;
	jPipeline["name"] = descriptor->getName();
	jPipeline["author"] = descriptor->getAuthor();
	jPipeline["description"] = descriptor->getDescription();

	Json::Value* jModules = new Json::Value();
	for(int i = 0 ; i<descriptor->getChildModulesCount() ; i++)
		jModules->append(serialize_module(descriptor->getChildModuleDescriptor(i)));
	jPipeline["modules"] = *jModules;

	Json::Value* jInputEndpoints = new Json::Value();
	for(int i=0 ; i<descriptor->getInputEndpointsCount() ; i++)
		jInputEndpoints->append(serialize_endpoint(descriptor->getInputEndpointDescriptor(i)));
	jPipeline["inputEndpoints"] = *jInputEndpoints;

	Json::Value* jOutputEndpoints = new Json::Value();
	for(int i=0 ; i<descriptor->getOutputEndpointsCount() ; i++)
		jOutputEndpoints->append(serialize_endpoint(descriptor->getOutputEndpointDescriptor(i)));
	jPipeline["outputEndpoints"] = *jOutputEndpoints;

	Json::Value* connections = new Json::Value();
	for (int i = 0 ; i<descriptor->getDataStreamDescriptorCount() ; i++)
		connections->append(serialize_connection(descriptor->getDataStreamDescriptor(i)));
	jPipeline["connections"] = *connections;

	return jPipeline;
}

Json::Value nuiJsonRpcApi::serialize_module( nuiModuleDescriptor* descriptor )
{
	Json::Value jModule;
	jModule["name"] = descriptor->getName();
	jModule["author"] = descriptor->getAuthor();
	jModule["description"] = descriptor->getDescription();

	Json::Value* jInputEndpoints = new Json::Value();
	for(int i=0 ; i<descriptor->getInputEndpointsCount() ; i++)
		jInputEndpoints->append(serialize_endpoint(descriptor->getInputEndpointDescriptor(i)));
	jModule["inputEndpoints"] = *jInputEndpoints;

	Json::Value* jOutputEndpoints = new Json::Value();
	for(int i=0 ; i<descriptor->getOutputEndpointsCount() ; i++)
		jOutputEndpoints->append(serialize_endpoint(descriptor->getOutputEndpointDescriptor(i)));
	jModule["outputEndpoints"] = *jOutputEndpoints;

	Json::Value* connections = new Json::Value();
	for (int i = 0 ; i<descriptor->getDataStreamDescriptorCount() ; i++)
		connections->append(serialize_connection(descriptor->getDataStreamDescriptor(i)));
	jModule["connections"] = *connections;

	return jModule;
}

Json::Value nuiJsonRpcApi::serialize_endpoint( nuiEndpointDescriptor *descriptor )
{
	Json::Value jEndpoint;
	jEndpoint["index"] = descriptor->getIndex();
	jEndpoint["descriptor"] = descriptor->getDescriptor();

	return jEndpoint;
}

Json::Value nuiJsonRpcApi::serialize_connection( nuiDataStreamDescriptor *descriptor )
{
	Json::Value jConnection;
	jConnection["sourceModule"] = descriptor->sourceModuleID;
	jConnection["sourcePort"] = descriptor->sourcePort;
	jConnection["destinationModule"] = descriptor->destinationModuleID;
	jConnection["destinationPort"] = descriptor->destinationPort;

	jConnection["buffered"] = (int)descriptor->buffered;
	jConnection["bufferSize"] = (int)descriptor->bufferSize;
	jConnection["deepCopy"] = (int)descriptor->deepCopy;
	jConnection["asyncMode"] = (int)descriptor->asyncMode;
	jConnection["lastPacket"] = (int)descriptor->lastPacket;
	jConnection["overflow"] = (int)descriptor->overflow;

	return jConnection;
}

void nuiJsonRpcApi::setFailure( Json::Value &responce )
{
	responce["result"] = "failure";
}

void nuiJsonRpcApi::setSuccess( Json::Value &responce )
{
	responce["result"] = "success";
}

bool nuiJsonRpcApi::isFinished()
{
	return finished;
}
