#include "ccf.h"

LOG_DECLARE("App");

static bool want_quit = false;
static bool config_syslog = false;
static nuiJsonRpcApi *server = NULL;
int g_config_delay = 20;

bool want_quit_soon = false;

static void signal_term(int signal) 
{
	want_quit = true;
}

int main(int argc, char **argv) 
{
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

	server = nuiJsonRpcApi::getInstance();
	server->startApi();

do
    {
		SLEEP(g_config_delay);
	} while ( server->isFinished() == false );

	nuiFrameworkManager::getInstance()->workflowStop();
	nuiFrameworkManager::getInstance()->workflowQuit();

exit_standard:
	// no server cleanup needed, done in thread
	return exit_ret;

exit_critical:
	exit_ret = 1;
	goto exit_standard;
}