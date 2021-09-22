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
		cout << "������ִ������:" << endl;
		cout << "\tdebug   ���ԣ�debug xx.exe��" << endl;
		cout << "\th �鿴��������" << endl;
		cout << "\tq �˳�" << endl;
		getline(cin, strcmd);

		if (strcmd == "q")
		{
			return 0;
		}
		else if (strcmd == "h")
		{
			cout << "********************OllyLesDbg�����ĵ�*******************" << endl;
			cout << "												" << endl;
			cout << "    1. T ���� P ���� G/G+ADDR ִ��							" << endl;
			cout << "    2. U/U+ADDR ��ʾ�����								" << endl;
			cout << "    3. D/D+ADDR �鿴�ڴ�								" << endl;
			cout << "    4. E+ADDR+CODE �޸��ڴ�								" << endl;
			cout << "    5. R �鿴�Ĵ���										" << endl;
			cout << "    6. BP+ADDRIN3 �ϵ� BL �鿴 BC+n���						" << endl;
			cout << "    7. R/R+ADDR ��ʾ�Ĵ�����Ϣ							" << endl;
			cout << "    8. bh+Addr+1/2/4+a/e/wӲ���ϵ� BHL�鿴 BHC+nɾ�� " << endl;
			cout << "    9. bm+addr+len+r/w�ڴ�ϵ� BML�鿴 BPC+1/2/3ɾ��		" << endl;
			cout << "    10. TRACE+P/T+ADDR ��/����CALL��¼ָ��							" << endl;
			cout << "    11. Q �˳�									" << endl;
			cout << "    12. H �鿴�����ĵ�				" << endl;
			cout << "                                                " << endl;
			cout << "*****************************************************" << endl;
			system("pause");
		}
		else if (strcmd.substr(0, 5) == "debug" && strcmd.length()>6)
		{
			strproc = strcmd.substr(6);

			//1���������ԻỰ
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
				cout << "û���ҵ����Ե�exe����·������������ȷ������(q:quit / debug xxx.exe): " << endl;
			}

		}
		else
		{
			cout << "���������������ȷ������(q:quit / debug xxx.exe): " << endl;;
		}
	}

	return 0;
}

VOID CDebugger::RunDebugLoop()
{
	//ѭ���ȴ������¼����쳣�� 
	while (WaitForDebugEvent(&m_de, INFINITE))
	{
		m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_de.dwThreadId);
		DWORD dwResult = DBG_CONTINUE; // �����������
		//3�������¼�
		switch (m_de.dwDebugEventCode)
		{
		case  EXCEPTION_DEBUG_EVENT:		//�����¼�
 			dwResult = OnExceptionDebugEvent();  
			break;
		case  CREATE_THREAD_DEBUG_EVENT:
			break;
		case  CREATE_PROCESS_DEBUG_EVENT:	//���������߳�
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
		//�ύ
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
	char strOpcode[MAXBYTE] = {};      // ������������Ϣ
	Decode2AsmOpcode(aryCode, szAsm, strOpcode, &nAsmLen, (UINT)pAddr);

	if (m_bTraceCmd == 1 ) //����traceָ�����
	{
		LPTSTR szBuffer = new TCHAR[32];//���岢�������뻺�����ռ� 
		wsprintf(szBuffer,"%p %s \r\n", pAddr, szAsm);//Ӧ
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

		//�����հ��ַ�
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
				DWORD dwAddr = strtoul(pCmd, NULL, 16);//��ȡ6���Ƶ�ַ
				if (dwAddr == 0)
				{
					break;
				}
				//���öϵ�
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
				DWORD dwAddr = strtoul(pCmd, NULL, 16);//��ȡ6���Ƶ�ַ
				if (dwAddr == 0)
				{
					break;
				}
				OnBCCommmd(dwAddr);
				break;
			}
			case 'h':
			case 'H'://Ӳ���ϵ�-804�����쳣
			{
				//bh addr len a/e/w
				++pCmd; 
				pCmd = SkipWhiteChar(pCmd);

				//��ȡ��ַ
				char* pCmdTmp = NULL;
				DWORD dwAddr = strtoul(pCmd, &pCmdTmp, 16);
				if (dwAddr == 0)
				{
					printf("[inf] ��ַ��������\r\n");
					break;
				}

				//��ȡ����
				pCmd = SkipWhiteChar(pCmdTmp);
				DWORD dwLen = strtol(pCmd, &pCmdTmp, 16);
				if (!(dwLen == 1 || dwLen == 2 || dwLen == 4))
				{
					printf("���Ƚ�������ֵ������1,2,4\r\n");
					break;
				}
				//��ȡ���� 
				pCmd = SkipWhiteChar(pCmdTmp);
				BYTE btHpType = 0;
				switch (*pCmd)
				{
				case 'a':
					btHpType = 3; //������11
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

				//��ȡ��ַ
				char* pCmdTmp = NULL;
				bmCmd.m_dwAddr = strtoul(pCmd, &pCmdTmp, 16);
				if (bmCmd.m_dwAddr == 0)
				{
					printf("[inf] ��ַ�������� \r\n");
					break;
				}

				//��ȡ����
				pCmd = SkipWhiteChar(pCmdTmp);
				bmCmd.m_dwLen = strtoul(pCmd, &pCmdTmp, 16);
				if (bmCmd.m_dwLen == 0)
				{
					printf("[inf] ���Ƚ������� \r\n");
					break;
				}

				//��ȡ����
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
					printf("[inf] �ڴ�ϵ�����ʧ�ܣ�����ֻ����r/w \r\n");
					continue;
				}
				//�����ڴ�ϵ�
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
			//trace addr p/t t��call t����call ������Ĭ�Ϲ�call
			if (pCmd[1] == 'r' && pCmd[2] == 'a' && pCmd[3] == 'c' && pCmd[4] == 'e')
			{
				pCmd+=5;
				pCmd = SkipWhiteChar(pCmd);
				dwTraceEndAddr = strtoul(pCmd, NULL, 16);//��ȡ16���Ƶ�ַ		
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
			DWORD dwAddr = strtoul(pCmd, NULL, 16);//��ȡ6���Ƶ�ַ
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
			//��ȡg����ĵ�ַ
			pCmd = SkipWhiteChar(pCmd);
			DWORD dwAddr = strtoul(pCmd, NULL, 16);
			if (dwAddr == 0)
			{
				OnDCommand(0);
				break;
			}
			//��ʾ�ڴ�
			OnDCommand(dwAddr);
			break;
		}
		case 'g':
		case 'G':
		{
			++pCmd;
			pCmd = SkipWhiteChar(pCmd);
			DWORD dwAddr = strtoul(pCmd, NULL, 16);//��ȡ6���Ƶ�ַ
			if (dwAddr == 0)
			{
				return;
			}
			//���öϵ�
			OnGCommand(dwAddr);
			return;
		}
		case'h':
		{
			cout << "********************OllyLesDbg�����ĵ�*******************" << endl;
			cout << "												" << endl;
			cout << "    1. T ���� P ���� G/G+ADDR ִ��							" << endl;
			cout << "    2. U/U+ADDR ��ʾ�����								" << endl;
			cout << "    3. D/D+ADDR �鿴�ڴ�								" << endl;
			cout << "    4. E+ADDR+CODE �޸��ڴ�								" << endl;
			cout << "    5. R �鿴�Ĵ���										" << endl;
			cout << "    6. BP+ADDRIN3 �ϵ� BL �鿴 BC+n���						" << endl;
			cout << "    7. R/R+ADDR ��ʾ�Ĵ�����Ϣ							" << endl;
			cout << "    8. bh+Addr+1/2/4+a/e/wӲ���ϵ� BHL�鿴 BHC+nɾ�� " << endl;
			cout << "    9. bm+addr+len+r/w�ڴ�ϵ� BML�鿴 BPC+1/2/3ɾ��		" << endl;
			cout << "    10. TRACE+P/T+ADDR ��/����CALL��¼ָ��							" << endl;
			cout << "    11. Q �˳�									" << endl;
			cout << "    12. H �鿴�����ĵ�				" << endl;
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

	//��ȡ���ڴ洦�ڴ���Ϣ��dwAddr��btOldCode
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
	pDr7->L0 = 1; //ʹ��DR0�Ĵ���
	pDr7->LEN0 = dwLen;
	pDr7->RW0 = btHpType;

	SetThreadContext(m_hThread, &ctx);

	return TRUE;
}

BOOL CDebugger::OnBpCommand(DWORD dwAddr)
{
	//���˶ϵ��Ƿ����
	for (auto& cmd : m_vctBpCmds)
	{
		if (cmd.m_dwAddr == dwAddr)
		{
			return FALSE;
		}
	}
	//���öϵ�
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

	//���õ�����־
	SetFAndDecEip();
	return TRUE;
}

BOOL CDebugger::OnPCommand()
{
	LPVOID pAddr = m_de.u.Exception.ExceptionRecord.ExceptionAddress;

	BYTE aryCode[16] = {};
	DWORD dwBytesTorRead = 0;
	ReadProcessMemory(m_hProc, pAddr, aryCode, sizeof(aryCode), &dwBytesTorRead);

	//�ȷ�����ж��ǲ���CALL
	char szAsm[MAXBYTE] = {};
	UINT nAsmLen = 0;
	Decode2Asm(aryCode, szAsm, &nAsmLen, (UINT)pAddr);

	//�ж��Ƿ���call
	if (strstr(szAsm, "call") != NULL)
	{
		 if (m_bTraceCmd == 1 && m_bTraceType == 0) //trace��callָ��
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
	//������ʱ�ϵ�
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
	//����DLL
	LOAD_DLL_DEBUG_INFO& lddi = m_de.u.LoadDll;

	//�ȶ���ַ
	LPVOID pAddr = 0;
	DWORD dwBytesToRead = 0;
	BOOL bRet = ReadProcessMemory(m_hProc, lddi.lpImageName, &pAddr, sizeof(pAddr), &dwBytesToRead);

	if (!bRet)
	{
		return DBG_CONTINUE;
	}
	//������
	if (lddi.fUnicode)
	{
		//unicode�����ʽ
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
	// д��ϵ㴦ԭ���Ĵ���
	BOOL bRet = WriteProcessMemory(m_hProc, (LPVOID)dwAddr, &btOldCode, sizeof(btOldCode), &dwBytesToWrite);
	VirtualProtectEx(m_hProc, (LPVOID)dwAddr, sizeof(btOldCode), dwOldProc, &dwOldProc);
}


DWORD CDebugger::OnExceptionDebugEvent()
{
	EXCEPTION_RECORD& er = m_de.u.Exception.ExceptionRecord;//�쳣�ṹ��er
	DWORD dwResult = DBG_CONTINUE;

	//ÿ�ε����¼����ٶ���¼�µ�ǰ��ʱ��ַ
	dwTempAddr = (DWORD)m_de.u.Exception.ExceptionRecord.ExceptionAddress;

	//�ж��ǲ���ϵͳ�ϵ�
	if (m_bIsSystemBp)
	{
		ShowAsmInfo();
		InputCommand(); //������������

		m_bIsSystemBp = FALSE;
		return dwResult;
	}

	switch (er.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT:
		dwResult = OnBreakPoint();  //�ϵ�
		break;
	case EXCEPTION_SINGLE_STEP:
		dwResult = OnSingleStep();   //����
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
	auto& er = m_de.u.Exception.ExceptionRecord;//���쳣��¼

	//�ж��Ƿ����жϵ�
	for (auto& cmd : m_vctBmCmds)
	{
		//�ж������ַ�Ƿ����е��ϵ�
		if ((ULONG_PTR)cmd.m_dwAddr <= er.ExceptionInformation[1]
			&& er.ExceptionInformation[1] <= (ULONG_PTR)(cmd.m_dwAddr + cmd.m_dwLen))
		{
			//�ж�����
			if (er.ExceptionInformation[0] == cmd.m_dwType)
			{
				//����
				ShowAsmInfo();
				InputCommand();


				//��ԭ�ڴ����ԣ��ϲ����
				SetFAndDecEip();

				DWORD dwOldProct = 0;
				BOOL bRet = VirtualProtectEx(m_hProc,
					(LPVOID)cmd.m_dwAddr,
					cmd.m_dwLen,
					cmd.m_dwOldProtect,
					&dwOldProct);

				//�ڵ���������ϵ�
				cmd.m_bReset = TRUE;

				break;
			}
		}

        //�ж��Ƿ���ͬһ����ҳ,��Ȼ�������öϵ��ַ��Χ�ڵ�ͬ��һ����ҳ
		if ((er.ExceptionInformation[1] & 0xfffff000) == (cmd.m_dwAddr & 0xfffff000))
		{

			//��ԭ�ڴ����ԣ��ϲ����
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
	
	//�ж��Ƿ�����ʱ�ϵ㣨����ʱ�������öϵ�����,��Ӱ��ԭ�жϵ㣬���ָ���ǰ���룩
	if (m_cmdTmp.m_dwAddr == (DWORD)m_de.u.Exception.ExceptionRecord.ExceptionAddress) 
	{
		ResumeBtCode(m_cmdTmp.m_dwAddr, m_cmdTmp.m_btOldCode);
		m_cmdTmp.m_dwAddr = NULL;
		bIsInputCommand = TRUE;
		DecEip();
	}
	
	//�ָ�ԭ����ָ��
	for (auto& cmd : m_vctBpCmds)
	{
		//���жϵ�
		if (cmd.m_dwAddr == (DWORD)m_de.u.Exception.ExceptionRecord.ExceptionAddress)
		{
			ResumeBtCode(cmd.m_dwAddr, cmd.m_btOldCode);
			//���õ���,Eip-1
			SetFAndDecEip(1);

			cmd.m_bReset = TRUE;//�뿪�öϵ����Ҫ����öϵ�
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
	ctx.EFlags |= 0x100;  //  ������־λ
	SetThreadContext(m_hThread, &ctx);

}


DWORD CDebugger::OnSingleStep()
{
	//����ϵ�
	for (auto& cmd : m_vctBpCmds)
	{
		if (cmd.m_bReset)
		{
			//��ʱ�ո��뿪���öϵ㣬��Ҫ�������öϵ�
			SetBp(cmd.m_dwAddr, &cmd.m_btOldCode);
			cmd.m_bReset = FALSE;
		}
	}

	//�����ڴ�ϵ�
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

	//����Ӳ���ϵ�
	if (m_bBhSingStep)
	{
		SetBh(m_bhCmd.m_dwAddr, m_bhCmd.m_dwLen, m_bhCmd.m_btType);
		m_bBhSingStep = FALSE;
	}

	//trace�Զ�����
	if (m_bTraceCmd)
	{
		ShowAsmInfo();
		//�ж��Ƿ���ֹͣ��λ��
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
			//û�е�ֹͣλ�ã����������
			OnPCommand();
			return DBG_CONTINUE;
		}
	}

	//����
	if (m_bSingStepCmd)
	{
		m_bSingStepCmd = FALSE;
		ShowAsmInfo();
		InputCommand();
	}

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(m_hThread, & ctx);

	//�ж�
	_DR6* pDr6 = (_DR6*)&ctx.Dr6;
	if (pDr6->B0)
	{
		//���õ���
		ctx.EFlags |= 0x100;
		m_bBhSingStep = TRUE;
		//ȡ��Ӳ���ϵ�
		_DR7* pDr7 = (_DR7*)&ctx.Dr7;
		pDr7->L0 = 0;

		RtlZeroMemory(pDr6, sizeof(_DR6));//DR6�Ĵ���ֻ��Ҫ���쳣ÿ���ύǰ���
		SetThreadContext(m_hThread, &ctx);

		//dr0��ַ�ϵ�����
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
	cout << "δ�ҵ�ָ��Ԫ��" << endl;
	return DBG_CONTINUE;
}

BOOL CDebugger::OnBMCommand(BMCommand& bmCmd)
{
	//�ж϶ϵ��Ƿ���ڣ��Ƿ�����/�����Ƿ�һ��/�Ƿ�ͬһ��ҳ��
	for (auto& cmdExt : m_vctBmCmds)
	{
		//�Ƿ����
		if (cmdExt.m_dwAddr == bmCmd.m_dwAddr)
		{
			printf("�ڴ�ϵ�����ʧ��");
			return FALSE;
		}
		//�Ƿ񽻲�
		if (cmdExt.m_dwAddr <= bmCmd.m_dwAddr &&
			bmCmd.m_dwAddr <= cmdExt.m_dwAddr + cmdExt.m_dwLen)
		{
			printf("[inf] �ڴ�ϵ�ʧ�ܣ����Ѵ��ڶϵ��н��� \r\n");
			return FALSE;
		}
		if (bmCmd.m_dwAddr <= cmdExt.m_dwAddr &&
			cmdExt.m_dwAddr <= bmCmd.m_dwAddr + bmCmd.m_dwLen)
		{
			printf("[inf] �ڴ�ϵ�ʧ�ܣ����Ѵ��ڶϵ��н��� \r\n");
			return FALSE;
		}
	}

	//�޸��ڴ�����
	BOOL bRet = VirtualProtectEx(
		m_hProc,
		(LPVOID)bmCmd.m_dwAddr,
		bmCmd.m_dwLen,
		PAGE_NOACCESS,
		&bmCmd.m_dwOldProtect);
	if (!bRet)
	{
		printf("[inf] �ڴ�ϵ�ʧ�ܣ������ڴ��Ƿ���� \r\n");
		return FALSE;
	}

	//����
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

