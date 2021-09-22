#include "CDebugger.h"

int main()
{
	CDebugger cdb;
	cdb.InitUI();
	cdb.Debug();
	cdb.RunDebugLoop();
	 
	return 0;
}