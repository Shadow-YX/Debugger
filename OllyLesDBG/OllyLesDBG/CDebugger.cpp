#include "CDebugger.h"
#include "Disasm/Decode2Asm.h"
#include <assert.h>
using namespace std;

BOOL CDebugger::Debug()
{
	string strcmd;
	string strproc;
	string strBpAddr;

	while (1)
	{
		cout << "请输入执行命令:" << endl;
		cout << "\tdebug   调试（debug xx.exe）" << endl;
		cout << "\th 查看调试命令" << endl;
		cout << "\tq 退出" << endl;
		getline(cin, strcmd);

		if (strcmd == "q")
		{
			return 0;
		}
		else if (strcmd == "h")
		{
			cout << "********************OllyLesDbg帮助文档*******************" << endl;
			cout << "												" << endl;
			cout << "    1. T 步入 P 步过 G/G+ADDR 执行							" << endl;
			cout << "    2. U/U+ADDR 显示反汇编								" << endl;
			cout << "    3. D/D+ADDR 查看内存								" << endl;
			cout << "    4. E+ADDR+CODE 修改内存								" << endl;
			cout << "    5. R 查看寄存器										" << endl;
			cout << "    6. BP+ADDRIN3 断点 BL 查看 BC+n清除						" << endl;
			cout << "    7. R/R+ADDR 显示寄存器信息							" << endl;
			cout << "    8. bh+Addr+1/2/4+a/e/w硬件断点 BHL查看 BHC+n删除 " << endl;
			cout << "    9. bm+addr+len+r/w内存断点 BML查看 BPC+1/2/3删除		" << endl;
			cout << "    10. TRACE+P/T+ADDR 过/不过CALL记录指令							" << endl;
			cout << "    11. Q 退出									" << endl;
			cout << "    12. H 查看帮助文档				" << endl;
			cout << "                                                " << endl;
			cout << "*****************************************************" << endl;
			system("pause");
		}
		else if (strcmd.substr(0, 5) == "debug" && strcmd.length()>6)
		{
			strproc = strcmd.substr(6);

			//1）建立调试会话
			STARTUPINFO si = {};
			PROCESS_INFORMATION pi = {};
			si.cb = sizeof(si);
			BOOL bRet = CreateProcess(NULL,
				(LPSTR)strproc.c_str(),
				NULL,
				NULL,
				FALSE,
				DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
				NULL,
				NULL,
				&si,
				&pi
			);
			if (bRet)
			{
				CloseHandle(pi.hThread);
				m_hProc = pi.hProcess;
				return TRUE;
			}
			else if(!bRet)
			{
				cout << "没有找到调试的exe程序路径！请输入正确的命令(q:quit / debug xxx.exe): " << endl;
			}

		}
		else
		{
			cout << "输入错误！请输入正确的命令(q:quit / debug xxx.exe): " << endl;;
		}
	}

	return 0;
}

VOID CDebugger::RunDebugLoop()
{
	//循环等待调试事件（异常） 
	while (WaitForDebugEvent(&m_de, INFINITE))
	{
		m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_de.dwThreadId);
		DWORD dwResult = DBG_CONTINUE; // 程序继续运行
		//3）处理事件
		switch (m_de.dwDebugEventCode)
		{
		case  EXCEPTION_DEBUG_EVENT:		//调试事件
 			dwResult = OnExceptionDebugEvent();  
			break;
		case  CREATE_THREAD_DEBUG_EVENT:
			break;
		case  CREATE_PROCESS_DEBUG_EVENT:	//创建调试线程
			break;
		case  EXIT_THREAD_DEBUG_EVENT:
			break;
		case  EXIT_PROCESS_DEBUG_EVENT:
			break;
		case  LOAD_DLL_DEBUG_EVENT:
			dwResult = OnLoadDllDEbugEvent();
			break;
		case  UNLOAD_DLL_DEBUG_EVENT:
			break;
		case  OUTPUT_DEBUG_STRING_EVENT:
			break;
		default:
			break;
		}
		//提交
		ContinueDebugEvent(m_de.dwProcessId, m_de.dwThreadId, dwResult);
	}
	return ;
}


VOID CDebugger::InitUI()
{
	cout << "			*****************************************************\r\n";
	cout << "			*                                                   *\r\n";
	cout << "			*                                                   *\r\n";
	cout << "			*               OllyLesDebug v1.0                   *\r\n";
	cout << "			*                                                   *\r\n";
	cout << "			*                                                   *\r\n";
	cout << "			*                    help:                          *\r\n";
	cout << "			*                       -debug xx.exe               *\r\n";
	cout << "			*                       -h ShowDebugCmd             *\r\n";
	cout << "			*                       -q Quit                     *\r\n";
	cout << "			*                                                   *\r\n";
	cout << "			*                                                   *\r\n";
	cout << "			*****************************************************\r\n";

}

VOID CDebugger::ShowAsmInfo()
{


	LPVOID pAddr = m_de.u.Exception.ExceptionRecord.ExceptionAddress;

	BYTE aryCode[16] = {};
	DWORD dwBytesToRead = 0;
	ReadProcessMemory(m_hProc, pAddr, aryCode, sizeof(aryCode), &dwBytesToRead);
	char szAsm[MAXBYTE] = {};
	UINT nAsmLen = 0;
	char strOpcode[MAXBYTE] = {};      // 解析机器码信息
	Decode2AsmOpcode(aryCode, szAsm, strOpcode, &nAsmLen, (UINT)pAddr);

	if (m_bTraceCmd == 1 ) //保存trace指令到数组
	{
		LPTSTR szBuffer = new TCHAR[32];//定义并申请输入缓冲区空间 
		wsprintf(szBuffer,"%p %s \r\n", pAddr, szAsm);//应
		DWORD bytesWritten = 0;
		SetFilePointer(hTraceFile, 0, NULL, FILE_END);
		int n = strlen(szBuffer);
		BOOL bRet=WriteFile(hTraceFile,szBuffer,strlen(szBuffer), &bytesWritten, NULL);
	}


	printf("[INF]: %p %s \r\n", pAddr, szAsm);
}

VOID CDebugger::InputCommand()
{
	while (TRUE)
	{
		printf("[cmd]:");
		char szCommand[MAXBYTE] = {};
		scanf("%255[^\n]", szCommand);
		rewind(stdin);

		//跳过空白字符
		char* pCmd = SkipWhiteChar(szCommand);
		switch (*pCmd)
		{
		case 'b':
		case 'B':
		{
			++pCmd;
			switch (*pCmd)
			{
			case 'p':
			case 'P':
			{
				++pCmd;
				pCmd = SkipWhiteChar(pCmd);
				DWORD dwAddr = strtoul(pCmd, NULL, 16);//获取6进制地址
				if (dwAddr == 0)
				{
					break;
				}
				//设置断点
 				OnBpCommand(dwAddr);
				break;
			}
			case 'L':
			case'l':
				OnBLCommmd();
				break;
			case 'c':
			case 'C':
			{
				++pCmd;
				pCmd = SkipWhiteChar(pCmd);
				DWORD dwAddr = strtoul(pCmd, NULL, 16);//获取6进制地址
				if (dwAddr == 0)
				{
					break;
				}
				OnBCCommmd(dwAddr);
				break;
			}
			case 'h':
			case 'H'://硬件断点-804单步异常
			{
				//bh addr len a/e/w
				++pCmd; 
				pCmd = SkipWhiteChar(pCmd);

				//获取地址
				char* pCmdTmp = NULL;
				DWORD dwAddr = strtoul(pCmd, &pCmdTmp, 16);
				if (dwAddr == 0)
				{
					printf("[inf] 地址解析出错\r\n");
					break;
				}

				//获取长度
				pCmd = SkipWhiteChar(pCmdTmp);
				DWORD dwLen = strtol(pCmd, &pCmdTmp, 16);
				if (!(dwLen == 1 || dwLen == 2 || dwLen == 4))
				{
					printf("长度解析错误，值必须是1,2,4\r\n");
					break;
				}
				//获取类型 
				pCmd = SkipWhiteChar(pCmdTmp);
				BYTE btHpType = 0;
				switch (*pCmd)
				{
				case 'a':
					btHpType = 3; //二进制11
					break;
				case'e':
					btHpType = 0; //00
					dwLen = 0;
					break; 
				case'w':
					btHpType = 1;//01
					break;
				default:
					break;
				}
				m_bhCmd.m_dwAddr = dwAddr;
				m_bhCmd.m_dwLen = dwLen;
				m_bhCmd.m_btType = btHpType;

				SetBh(dwAddr, dwLen, btHpType);
				break;
			}
			case 'M':
			case 'm':
			{
				++pCmd;
				pCmd = SkipWhiteChar(pCmd);
				BMCommand bmCmd;

				//获取地址
				char* pCmdTmp = NULL;
				bmCmd.m_dwAddr = strtoul(pCmd, &pCmdTmp, 16);
				if (bmCmd.m_dwAddr == 0)
				{
					printf("[inf] 地址解析出错 \r\n");
					break;
				}

				//获取长度
				pCmd = SkipWhiteChar(pCmdTmp);
				bmCmd.m_dwLen = strtoul(pCmd, &pCmdTmp, 16);
				if (bmCmd.m_dwLen == 0)
				{
					printf("[inf] 长度解析出错 \r\n");
					break;
				}

				//获取类型
				pCmd = SkipWhiteChar(pCmdTmp);
				BYTE btHpType = 0;
				switch (*pCmd)
				{
				case 'r':
					bmCmd.m_dwType = BT_READ;
					break;
				case 'w':
					bmCmd.m_dwType = BT_WRITE;
					break;
				default:
					printf("[inf] 内存断点设置失败，类型只能是r/w \r\n");
					continue;
				}
				//设置内存断点
				OnBMCommand(bmCmd);
				break;

			}
			default:
				break;
			}
			break;
		}
		case 't':
		case 'T':
			//trace addr p/t t过call t不过call ，不加默认过call
			if (pCmd[1] == 'r' && pCmd[2] == 'a' && pCmd[3] == 'c' && pCmd[4] == 'e')
			{
				pCmd+=5;
				pCmd = SkipWhiteChar(pCmd);
				dwTraceEndAddr = strtoul(pCmd, NULL, 16);//获取16进制地址		
				m_bTraceType = 0;
				int nlen= strlen(pCmd)-2;
				pCmd += nlen;
				pCmd = SkipWhiteChar(pCmd);
				if (*pCmd == 'p'|| (char)pCmd == 'P')
				{
					m_bTraceType = 1;
				}
				OnTraceCommand();
			}
			else
			{
				OnTCommand();
			}
			return;
		case 'p':
		case 'P':
			OnPCommand();
			return;
		case 'U':
		case 'u':
		{
			++pCmd;
			pCmd = SkipWhiteChar(pCmd);
			DWORD dwAddr = strtoul(pCmd, NULL, 16);//获取6进制地址
			if (dwAddr == 0)
			{
				if (dwTempAddr != 0)
				{
					OnUCommand(dwTempAddr);
					break;
				}
				OnUCommand0();
				break;
			}
			OnUCommand(dwAddr);
			break;
		}
		case 'r':
		case 'R':
		{
			OnRCommand();
			break;
		}
		case 'd':
		case 'D':
		{
			++pCmd;
			//获取g后面的地址
			pCmd = SkipWhiteChar(pCmd);
			DWORD dwAddr = strtoul(pCmd, NULL, 16);
			if (dwAddr == 0)
			{
				OnDCommand(0);
				break;
			}
			//显示内存
			OnDCommand(dwAddr);
			break;
		}
		case 'g':
		case 'G':
		{
			++pCmd;
			pCmd = SkipWhiteChar(pCmd);
			DWORD dwAddr = strtoul(pCmd, NULL, 16);//获取6进制地址
			if (dwAddr == 0)
			{
				return;
			}
			//设置断点
			OnGCommand(dwAddr);
			return;
		}
		case'h':
		{
			cout << "********************OllyLesDbg帮助文档*******************" << endl;
			cout << "												" << endl;
			cout << "    1. T 步入 P 步过 G/G+ADDR 执行							" << endl;
			cout << "    2. U/U+ADDR 显示反汇编								" << endl;
			cout << "    3. D/D+ADDR 查看内存								" << endl;
			cout << "    4. E+ADDR+CODE 修改内存								" << endl;
			cout << "    5. R 查看寄存器										" << endl;
			cout << "    6. BP+ADDRIN3 断点 BL 查看 BC+n清除						" << endl;
			cout << "    7. R/R+ADDR 显示寄存器信息							" << endl;
			cout << "    8. bh+Addr+1/2/4+a/e/w硬件断点 BHL查看 BHC+n删除 " << endl;
			cout << "    9. bm+addr+len+r/w内存断点 BML查看 BPC+1/2/3删除		" << endl;
			cout << "    10. TRACE+P/T+ADDR 过/不过CALL记录指令							" << endl;
			cout << "    11. Q 退出									" << endl;
			cout << "    12. H 查看帮助文档				" << endl;
			cout << "                                                " << endl;
			cout << "*****************************************************" << endl;
			break;
		}
		case'q':
		case'Q':
			exit(0);
		default:
			break;
		}
	}
	
}

char* CDebugger::SkipWhiteChar(char* pCommand)
{
	while (*pCommand == ' ' || *pCommand == '\t')
	{
		++pCommand;
	}
	return pCommand;
}

BOOL CDebugger::SetBp(DWORD dwAddr, LPBYTE btOldCode)
{
	BYTE btCode = 0xcc;
	DWORD dwOldProc = 0;
	VirtualProtectEx(m_hProc, (LPVOID)dwAddr, sizeof(dwAddr), PAGE_READWRITE, &dwOldProc);
	DWORD dwBytesToRead = 0;

	//获取该内存处内存信息到dwAddr和btOldCode
	BOOL bRet = ReadProcessMemory(m_hProc, (LPVOID)dwAddr, btOldCode, sizeof(BYTE), &dwBytesToRead);
	DWORD dwBytesToWrite = 0;
	bRet = WriteProcessMemory(m_hProc, (LPVOID)dwAddr, &btCode, sizeof(btCode), &dwBytesToWrite);
	VirtualProtectEx(m_hProc, (LPVOID)dwAddr, sizeof(dwAddr), dwOldProc, &dwOldProc);

	return TRUE;
}

BOOL CDebugger::SetBh(DWORD dwAddr, DWORD dwLen, BYTE btHpType)
{
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(m_hThread, &ctx);

	ctx.Dr0 = dwAddr;
	_DR7* pDr7 = (_DR7*)&ctx.Dr7;
	pDr7->L0 = 1; //使用DR0寄存器
	pDr7->LEN0 = dwLen;
	pDr7->RW0 = btHpType;

	SetThreadContext(m_hThread, &ctx);

	return TRUE;
}

BOOL CDebugger::OnBpCommand(DWORD dwAddr)
{
	//检查此断点是否存在
	for (auto& cmd : m_vctBpCmds)
	{
		if (cmd.m_dwAddr == dwAddr)
		{
			return FALSE;
		}
	}
	//设置断点
	BYTE btOldCode = 0;
	if (SetBp(dwAddr, &btOldCode))
	{
		m_vctBpCmds.push_back(BpCommand{dwAddr, btOldCode,FALSE });
		return TRUE;
	}
	return FALSE;
}

BOOL CDebugger::OnTCommand()
{
	m_bSingStepCmd = TRUE;

	//设置单步标志
	SetFAndDecEip();
	return TRUE;
}

BOOL CDebugger::OnPCommand()
{
	LPVOID pAddr = m_de.u.Exception.ExceptionRecord.ExceptionAddress;

	BYTE aryCode[16] = {};
	DWORD dwBytesTorRead = 0;
	ReadProcessMemory(m_hProc, pAddr, aryCode, sizeof(aryCode), &dwBytesTorRead);

	//先反汇编判断是不是CALL
	char szAsm[MAXBYTE] = {};
	UINT nAsmLen = 0;
	Decode2Asm(aryCode, szAsm, &nAsmLen, (UINT)pAddr);

	//判断是否是call
	if (strstr(szAsm, "call") != NULL)
	{
		 if (m_bTraceCmd == 1 && m_bTraceType == 0) //trace到call指令
		{
			 SetFAndDecEip();
			 m_bSingStepCmd = TRUE;
			return DBG_CONTINUE;
		}

		DWORD dwNextAddr = (DWORD)pAddr + nAsmLen;
		m_cmdTmp = { dwNextAddr,0,FALSE };
		SetBp(dwNextAddr, &m_cmdTmp.m_btOldCode);
	}
	else
	{
		SetFAndDecEip();
		m_bSingStepCmd = TRUE;
	}

	return TRUE;
}

BOOL CDebugger::OnGCommand(DWORD dwAddr)
{
	//设置临时断点
	BYTE btOldCode = 0;
	if (SetBp(dwAddr, &btOldCode))
	{
		m_cmdTmp = { dwAddr,btOldCode,FALSE };
		return TRUE;
	}
	return FALSE;
}



DWORD CDebugger::OnLoadDllDEbugEvent()
{
	//解析DLL
	LOAD_DLL_DEBUG_INFO& lddi = m_de.u.LoadDll;

	//先读地址
	LPVOID pAddr = 0;
	DWORD dwBytesToRead = 0;
	BOOL bRet = ReadProcessMemory(m_hProc, lddi.lpImageName, &pAddr, sizeof(pAddr), &dwBytesToRead);

	if (!bRet)
	{
		return DBG_CONTINUE;
	}
	//读名称
	if (lddi.fUnicode)
	{
		//unicode编码格式
		wchar_t szPath[MAX_PATH] = {};
		bRet = ReadProcessMemory(m_hProc, pAddr, szPath, sizeof(szPath), &dwBytesToRead);
		if (bRet)
		{
			printf("[info] %ws\r\n", szPath);
		}
	}
	else
	{
		//char
		char szPath[MAX_PATH] = {};
		bRet = ReadProcessMemory(m_hProc, pAddr, szPath, sizeof(szPath), &dwBytesToRead);
		if (bRet)
		{
			printf("[info] %s\r\n", szPath);
		}
	}
	return DBG_CONTINUE;
}


VOID CDebugger::ResumeBtCode(DWORD dwAddr, BYTE btOldCode)
{
	DWORD dwOldProc = 0;
	DWORD dwBytesToWrite = 0;

	VirtualProtectEx(m_hProc, (LPVOID)dwAddr, sizeof(btOldCode), PAGE_READWRITE, &dwOldProc);
	// 写入断点处原来的代码
	BOOL bRet = WriteProcessMemory(m_hProc, (LPVOID)dwAddr, &btOldCode, sizeof(btOldCode), &dwBytesToWrite);
	VirtualProtectEx(m_hProc, (LPVOID)dwAddr, sizeof(btOldCode), dwOldProc, &dwOldProc);
}


DWORD CDebugger::OnExceptionDebugEvent()
{
	EXCEPTION_RECORD& er = m_de.u.Exception.ExceptionRecord;//异常结构体er
	DWORD dwResult = DBG_CONTINUE;

	//每次调试事件来临都记录下当前临时地址
	dwTempAddr = (DWORD)m_de.u.Exception.ExceptionRecord.ExceptionAddress;

	//判断是不是系统断点
	if (m_bIsSystemBp)
	{
		ShowAsmInfo();
		InputCommand(); //接受输入命令

		m_bIsSystemBp = FALSE;
		return dwResult;
	}

	switch (er.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT:
		dwResult = OnBreakPoint();  //断点
		break;
	case EXCEPTION_SINGLE_STEP:
		dwResult = OnSingleStep();   //单步
		break;
	case EXCEPTION_ACCESS_VIOLATION:
		dwResult = OnAccessViolation();
	default:
		break;
	}

	return dwResult;
}

DWORD CDebugger::OnAccessViolation()
{
	DWORD dwResult = DBG_CONTINUE; 
	auto& er = m_de.u.Exception.ExceptionRecord;//拿异常记录

	//判断是否命中断点
	for (auto& cmd : m_vctBmCmds)
	{
		//判断这个地址是否命中到断点
		if ((ULONG_PTR)cmd.m_dwAddr <= er.ExceptionInformation[1]
			&& er.ExceptionInformation[1] <= (ULONG_PTR)(cmd.m_dwAddr + cmd.m_dwLen))
		{
			//判断类型
			if (er.ExceptionInformation[0] == cmd.m_dwType)
			{
				//命中
				ShowAsmInfo();
				InputCommand();


				//还原内存属性，断步配合
				SetFAndDecEip();

				DWORD dwOldProct = 0;
				BOOL bRet = VirtualProtectEx(m_hProc,
					(LPVOID)cmd.m_dwAddr,
					cmd.m_dwLen,
					cmd.m_dwOldProtect,
					&dwOldProct);

				//在单步中重设断点
				cmd.m_bReset = TRUE;

				break;
			}
		}

        //判断是否是同一个分页,虽然不在设置断点地址范围内但同属一个分页
		if ((er.ExceptionInformation[1] & 0xfffff000) == (cmd.m_dwAddr & 0xfffff000))
		{

			//还原内存属性，断步配合
			SetFAndDecEip();

			DWORD dwOldProct = 0;
			BOOL bRet = VirtualProtectEx(m_hProc,
				(LPVOID)cmd.m_dwAddr,
				cmd.m_dwLen,
				cmd.m_dwOldProtect,
				&dwOldProct);

			cmd.m_bReset = TRUE;
		}

	}

	return dwResult;
}

void CDebugger::DecEip()
{
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(m_hThread, &ctx);
	ctx.Eip -= 1;
	SetThreadContext(m_hThread, &ctx);
}

DWORD CDebugger::OnBreakPoint()
{
	BOOL bIsInputCommand = FALSE;
	
	//判断是否是临时断点（单步时碰到永久断点的情况,不影响原有断点，仅恢复当前代码）
	if (m_cmdTmp.m_dwAddr == (DWORD)m_de.u.Exception.ExceptionRecord.ExceptionAddress) 
	{
		ResumeBtCode(m_cmdTmp.m_dwAddr, m_cmdTmp.m_btOldCode);
		m_cmdTmp.m_dwAddr = NULL;
		bIsInputCommand = TRUE;
		DecEip();
	}
	
	//恢复原来的指令
	for (auto& cmd : m_vctBpCmds)
	{
		//命中断点
		if (cmd.m_dwAddr == (DWORD)m_de.u.Exception.ExceptionRecord.ExceptionAddress)
		{
			ResumeBtCode(cmd.m_dwAddr, cmd.m_btOldCode);
			//设置单步,Eip-1
			SetFAndDecEip(1);

			cmd.m_bReset = TRUE;//离开该断点后需要重设该断点
			bIsInputCommand = TRUE;
		}
	}

	if (bIsInputCommand)
	{
		ShowAsmInfo();

		if (m_bTraceCmd==1 )
		{
			OnPCommand();
			return DBG_CONTINUE;
		}

		InputCommand();
	}

	return DBG_CONTINUE;
}



VOID CDebugger::SetFAndDecEip(DWORD dwDecVal)
{
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(m_hThread, &ctx);
	ctx.Eip -= dwDecVal;
	ctx.EFlags |= 0x100;  //  单步标志位
	SetThreadContext(m_hThread, &ctx);

}


DWORD CDebugger::OnSingleStep()
{
	//重设断点
	for (auto& cmd : m_vctBpCmds)
	{
		if (cmd.m_bReset)
		{
			//这时刚刚离开永久断点，需要重新设置断点
			SetBp(cmd.m_dwAddr, &cmd.m_btOldCode);
			cmd.m_bReset = FALSE;
		}
	}

	//重设内存断点
	for (auto& cmd : m_vctBmCmds)
	{
		if (cmd.m_bReset)
		{
			cmd.m_bReset = FALSE;
			VirtualProtectEx(m_hProc,
				(LPVOID)cmd.m_dwAddr,
				cmd.m_dwLen,
				PAGE_NOACCESS,
				&cmd.m_dwOldProtect);
		}
	}

	//重设硬件断点
	if (m_bBhSingStep)
	{
		SetBh(m_bhCmd.m_dwAddr, m_bhCmd.m_dwLen, m_bhCmd.m_btType);
		m_bBhSingStep = FALSE;
	}

	//trace自动单步
	if (m_bTraceCmd)
	{
		ShowAsmInfo();
		//判断是否到了停止的位置
		if (m_de.u.Exception.ExceptionRecord.ExceptionAddress >= (LPVOID)dwTraceEndAddr)
		{
			m_bTraceCmd = FALSE;
			if (!hTraceFile)
			{
				CloseHandle(hTraceFile);
			}

			InputCommand();
			return DBG_CONTINUE;
		}
		else
		{
			//没有到停止位置，则继续单步
			OnPCommand();
			return DBG_CONTINUE;
		}
	}

	//单步
	if (m_bSingStepCmd)
	{
		m_bSingStepCmd = FALSE;
		ShowAsmInfo();
		InputCommand();
	}

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(m_hThread, & ctx);

	//判断
	_DR6* pDr6 = (_DR6*)&ctx.Dr6;
	if (pDr6->B0)
	{
		//设置单步
		ctx.EFlags |= 0x100;
		m_bBhSingStep = TRUE;
		//取消硬件断点
		_DR7* pDr7 = (_DR7*)&ctx.Dr7;
		pDr7->L0 = 0;

		RtlZeroMemory(pDr6, sizeof(_DR6));//DR6寄存器只需要在异常每次提交前清除
		SetThreadContext(m_hThread, &ctx);

		//dr0地址断点命中
		ShowAsmInfo();
		InputCommand();
	}
	else
	{
		RtlZeroMemory(pDr6, sizeof(_DR6));
		SetThreadContext(m_hThread, &ctx);
	}

	return DBG_CONTINUE;
}

BOOL CDebugger::OnBLCommmd()
{

	for (int i=0;i<m_vctBpCmds.size();i++)
	{
		printf("%d. ",i+1);
		printf("%d\r\n", m_vctBpCmds[i]);
	}

	return DBG_CONTINUE;
}

BOOL CDebugger::OnBCCommmd(DWORD dwAddr)
{
	vector<BpCommand>::iterator it;
	for (it = m_vctBpCmds.begin(); it != m_vctBpCmds.end();it++)
	{
		if (it->m_dwAddr ==dwAddr)
		{
			m_vctBpCmds.erase(it);
			return DBG_CONTINUE;
		}

	}
	cout << "未找到指定元素" << endl;
	return DBG_CONTINUE;
}

BOOL CDebugger::OnBMCommand(BMCommand& bmCmd)
{
	//判断断点是否存在（是否设置/类型是否一样/是否同一分页）
	for (auto& cmdExt : m_vctBmCmds)
	{
		//是否存在
		if (cmdExt.m_dwAddr == bmCmd.m_dwAddr)
		{
			printf("内存断点设置失败");
			return FALSE;
		}
		//是否交叉
		if (cmdExt.m_dwAddr <= bmCmd.m_dwAddr &&
			bmCmd.m_dwAddr <= cmdExt.m_dwAddr + cmdExt.m_dwLen)
		{
			printf("[inf] 内存断点失败，与已存在断点有交叉 \r\n");
			return FALSE;
		}
		if (bmCmd.m_dwAddr <= cmdExt.m_dwAddr &&
			cmdExt.m_dwAddr <= bmCmd.m_dwAddr + bmCmd.m_dwLen)
		{
			printf("[inf] 内存断点失败，与已存在断点有交叉 \r\n");
			return FALSE;
		}
	}

	//修改内存属性
	BOOL bRet = VirtualProtectEx(
		m_hProc,
		(LPVOID)bmCmd.m_dwAddr,
		bmCmd.m_dwLen,
		PAGE_NOACCESS,
		&bmCmd.m_dwOldProtect);
	if (!bRet)
	{
		printf("[inf] 内存断点失败，请检查内存是否存在 \r\n");
		return FALSE;
	}

	//保存
	m_vctBmCmds.push_back(bmCmd);
	return TRUE;

}

BOOL CDebugger::OnUCommand(DWORD dwAddr)
{
	for (UINT i = 0; i < 10; i++)
	{
		BYTE aryCode[16] = {};
		DWORD dwBytesToRead = 0;
		ReadProcessMemory(m_hProc, (LPVOID)dwAddr, aryCode, sizeof(aryCode), &dwBytesToRead);
		char szAsm[MAXBYTE] = {};
		UINT nAsmLen = 0;
		Decode2Asm(aryCode, szAsm, &nAsmLen, (UINT)dwAddr);

		printf("[INF]: %p %s \r\n", (LPVOID)dwAddr, szAsm);

		dwAddr = (UINT)dwAddr + nAsmLen;
	}
	dwTempAddr = dwAddr;

	return TRUE;
}

BOOL CDebugger::OnUCommand0()
{
	LPVOID pAddr = m_de.u.Exception.ExceptionRecord.ExceptionAddress;

	for (UINT i = 0; i < 10; i++)
	{
		BYTE aryCode[16] = {};
		DWORD dwBytesToRead = 0;
		ReadProcessMemory(m_hProc, pAddr, aryCode, sizeof(aryCode), &dwBytesToRead);
		char szAsm[MAXBYTE] = {};
		UINT nAsmLen = 0;
		Decode2Asm(aryCode, szAsm, &nAsmLen, (UINT)pAddr);
		printf("[INF]: %p %s \r\n", pAddr, szAsm);

		UINT npAddr =(UINT)pAddr+ nAsmLen;
		pAddr = (LPVOID)npAddr;
	}
	dwTempAddr = (DWORD)pAddr;

	return TRUE;
}

BOOL CDebugger::OnRCommand()
{
	CONTEXT ctx;
	FLAGS_REGISTER Flags;
	ctx.ContextFlags = CONTEXT_ALL;

	if (GetThreadContext(m_hThread, &ctx))
	{
		Flags.Flags = ctx.EFlags;
		printf("EAX = %08X  EBX = %08X  ECX = %08X  EDX = %08X  ESI = %08X  EDI = %08X\r\n",
			ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx, ctx.Esi, ctx.Edi);

		printf("EIP = %08X  ESP = %08X  EBP = %08X  CF  PF  AF  ZF  SF  TF  IF  DF  OF\r\n",
			ctx.Eip, ctx.Esp, ctx.Ebp, ctx.Edx, ctx.Esi, ctx.Edi);
		printf("                                                %02X  %02X  %02X  %02X  %02X  %02X  %02X  %02X  %02X\r\n",
			Flags.ZF, Flags.PF, Flags.AF,
			Flags.OF, Flags.SF, Flags.DF,
			Flags.CF, Flags.TF, Flags.IF);

		printf("CS = %04X  SS = %04X  DS = %04X  ES = %04X  FS = %04X   GS = %04X\r\n",
			ctx.SegCs, ctx.SegSs, ctx.SegDs, ctx.SegEs, ctx.SegFs, ctx.SegGs);

	}

	return TRUE;
}

BOOL CDebugger::OnDCommand(DWORD dwAddr)
{
	unsigned char szBuff[0x40] = { 0 };
	DWORD dwPreAddr;

	if (dwAddr == 0)
	{
		dwPreAddr = (DWORD)m_de.u.Exception.ExceptionRecord.ExceptionAddress;
	}
	else
	{
		dwPreAddr = dwAddr;
	}

	DWORD dwBytesToRead = 0;
	BOOL bRet = ReadProcessMemory(m_hProc, (LPVOID)dwPreAddr, szBuff, 0x40 * sizeof(BYTE), &dwBytesToRead);

	for (int i = 0; i < 4; i++)
	{
		printf("%08X ", dwPreAddr + i * 0x10);
		for (int j = 0; j < 0x10; j++)
			printf("%02X ", szBuff[i * 0x10 + j]);
		printf("  ");
		for (int j = 0; j < 0x10; j++)
		{
			if (szBuff[i * 0x10 + j] >= 0x20 && szBuff[i * 0x10 + j] <= 0x7F)
				printf("%c", szBuff[i * 0x10 + j]);
			else
				printf(".");
		}

		printf("\r\n");
	}
	return TRUE;
}

BOOL CDebugger::OnTraceCommand()
{
	hTraceFile= CreateFile("trace.txt",
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		0,
		NULL);

	m_bTraceCmd = TRUE;
	return OnPCommand();
}

