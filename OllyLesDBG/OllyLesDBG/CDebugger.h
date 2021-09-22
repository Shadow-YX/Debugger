#include<iostream>
#include<Windows.h>
#include<vector>
#include <algorithm>
#include <utility>
#include<string>

using namespace std;

//存放断点信息的结构体
struct BpCommand
{
	DWORD m_dwAddr; //地址
	BYTE m_btOldCode; //代码
	BOOL m_bReset = FALSE;
};

struct BhCommand
{
    DWORD m_dwAddr;
    DWORD m_dwLen;
    BYTE  m_btType;
};

enum Bmtype
{
    BT_READ = 0,
    BT_WRITE = 1
};

struct BMCommand
{
    DWORD m_dwAddr = 0;
    DWORD m_dwLen = 0;
    Bmtype m_dwType = BT_READ;
    DWORD m_dwOldProtect = 0;
    BOOL m_bReset = FALSE; //是否需要重设的标志
};



union  _DR7
{
    struct
    {
        unsigned int L0 : 1;
        unsigned int G0 : 1;
        unsigned int L1 : 1;
        unsigned int G1 : 1;
        unsigned int L2 : 1;
        unsigned int G2 : 1;
        unsigned int L3 : 1;
        unsigned int G3 : 1;
        unsigned int LE : 1;
        unsigned int GE : 1;
        unsigned int : 1;
        unsigned int RTM : 1;
        unsigned int : 1;
        unsigned int GD : 1;
        unsigned int : 2;
        unsigned int RW0 : 2;
        unsigned int LEN0 : 2;
        unsigned int RW1 : 2;
        unsigned int LEN1 : 2;
        unsigned int RW2 : 2;
        unsigned int LEN2 : 2;
        unsigned int RW3 : 2;
        unsigned int LEN3 : 2;
    };
    unsigned int dr7;
};

struct DR6
{
    unsigned int B0 : 1;
    unsigned int B1 : 1;
    unsigned int B2 : 1;
    unsigned int B3 : 1;
    unsigned int unuse : 28;
};

union  _DR6
{
    struct
    {
        unsigned int B0 : 1;
        unsigned int B1 : 1;
        unsigned int B2 : 1;
        unsigned int B3 : 1;
        unsigned int a : 9;
        unsigned int BD : 1;
        unsigned int BS : 1;
        unsigned int BT : 1;
        unsigned int RTM : 1;
        unsigned int b : 15;
    };
    unsigned int dr6;
};

union FLAGS_REGISTER
{
    unsigned int Flags;
    struct {
        unsigned int CF : 1;
        unsigned int : 1;
        unsigned int PF : 1;
        unsigned int : 1;
        unsigned int AF : 1;
        unsigned int : 1;
        unsigned int ZF : 1;
        unsigned int SF : 1;
        unsigned int TF : 1;
        unsigned int IF : 1;
        unsigned int DF : 1;
        unsigned int OF : 1;
    };
};


class CDebugger
{ 
public:
	BOOL Debug();
	VOID RunDebugLoop();
	VOID InitUI();

private:
	VOID ShowAsmInfo(); //反汇编，显示汇编代码
	VOID  InputCommand(); 	//接受输入命令
	char* SkipWhiteChar(char* pCommand); //跳过空白字符


private://处理命令
	BOOL SetBp(DWORD dwAddr, LPBYTE btOldCode);   //设置断点
    BOOL SetBh(DWORD dwAddr, DWORD dwLen, BYTE btHpType);//设置硬件断点
	BOOL OnBpCommand(DWORD dwAddr);  //断点命令
	BOOL OnTCommand();    // t单步跳过
	BOOL OnPCommand();  // p单步步过
	BOOL OnGCommand(DWORD dwAddr);  //  g执行	
	BOOL OnBLCommmd();// 列出所有断点
	BOOL OnBCCommmd(DWORD dwAddr);// 列出所有断点
    BOOL OnBMCommand(BMCommand& bmCmd);
	BOOL OnUCommand(DWORD dwAddr);//U显示指定地址10条反汇编指令
	BOOL OnUCommand0();//显示当前地址10条反汇编指令
    BOOL OnRCommand(); //R 显示寄存器信息
    BOOL OnDCommand(DWORD dwAddr); //D显示内存
	BOOL OnTraceCommand(); //追踪 
private:
	BOOL m_bIsSystemBp = TRUE; //是否是系统断点标志
    BOOL m_bBhSingStep = FALSE; //是否是硬件断点拿到单步标志
	BOOL m_bSingStepCmd = FALSE;//是否是T命令单步标志
	BOOL m_bTCommand=FALSE;
	BOOL m_bTraceCmd = FALSE;//Trace命令标志
    DWORD dwTraceEndAddr=0;// Trace命令结束地址
    DWORD m_bTraceType = 0; ;//Trace类型 默认过CALL，1不过CALL

	DEBUG_EVENT m_de;
	HANDLE m_hProc;
	HANDLE m_hThread;
	vector<BpCommand>m_vctBpCmds; //用来保存软件断点的数组
	BpCommand m_cmdTmp;   //保存临时断点
	DWORD dwTempAddr = 0;  //保存临时地址
    char szBuffer[0x10000] = { 0 };
    HANDLE hTraceFile;
private:
	DWORD OnLoadDllDEbugEvent();//显示DLL
	VOID ResumeBtCode(DWORD dwAddr,BYTE btOldCode); //还原原来的代码
	VOID SetFAndDecEip(DWORD dwDecVal = 0);   //单步异常
	DWORD  OnExceptionDebugEvent();// 处理调试事件
    DWORD OnAccessViolation();
    void DecEip();
    //内存访问权限异常 C05
	DWORD  OnBreakPoint();//断点异常 c803
	DWORD OnSingleStep();//单步异常 c804
    BhCommand m_bhCmd; //用来保存硬件断点
    vector<BMCommand> m_vctBmCmds;  //保存内存断点信息
};

