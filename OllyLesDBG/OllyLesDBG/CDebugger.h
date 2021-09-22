#include<iostream>
#include<Windows.h>
#include<vector>
#include <algorithm>
#include <utility>
#include<string>

using namespace std;

//��Ŷϵ���Ϣ�Ľṹ��
struct BpCommand
{
	DWORD m_dwAddr; //��ַ
	BYTE m_btOldCode; //����
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
    BOOL m_bReset = FALSE; //�Ƿ���Ҫ����ı�־
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
	VOID ShowAsmInfo(); //����࣬��ʾ������
	VOID  InputCommand(); 	//������������
	char* SkipWhiteChar(char* pCommand); //�����հ��ַ�


private://��������
	BOOL SetBp(DWORD dwAddr, LPBYTE btOldCode);   //���öϵ�
    BOOL SetBh(DWORD dwAddr, DWORD dwLen, BYTE btHpType);//����Ӳ���ϵ�
	BOOL OnBpCommand(DWORD dwAddr);  //�ϵ�����
	BOOL OnTCommand();    // t��������
	BOOL OnPCommand();  // p��������
	BOOL OnGCommand(DWORD dwAddr);  //  gִ��	
	BOOL OnBLCommmd();// �г����жϵ�
	BOOL OnBCCommmd(DWORD dwAddr);// �г����жϵ�
    BOOL OnBMCommand(BMCommand& bmCmd);
	BOOL OnUCommand(DWORD dwAddr);//U��ʾָ����ַ10�������ָ��
	BOOL OnUCommand0();//��ʾ��ǰ��ַ10�������ָ��
    BOOL OnRCommand(); //R ��ʾ�Ĵ�����Ϣ
    BOOL OnDCommand(DWORD dwAddr); //D��ʾ�ڴ�
	BOOL OnTraceCommand(); //׷�� 
private:
	BOOL m_bIsSystemBp = TRUE; //�Ƿ���ϵͳ�ϵ��־
    BOOL m_bBhSingStep = FALSE; //�Ƿ���Ӳ���ϵ��õ�������־
	BOOL m_bSingStepCmd = FALSE;//�Ƿ���T�������־
	BOOL m_bTCommand=FALSE;
	BOOL m_bTraceCmd = FALSE;//Trace�����־
    DWORD dwTraceEndAddr=0;// Trace���������ַ
    DWORD m_bTraceType = 0; ;//Trace���� Ĭ�Ϲ�CALL��1����CALL

	DEBUG_EVENT m_de;
	HANDLE m_hProc;
	HANDLE m_hThread;
	vector<BpCommand>m_vctBpCmds; //������������ϵ������
	BpCommand m_cmdTmp;   //������ʱ�ϵ�
	DWORD dwTempAddr = 0;  //������ʱ��ַ
    char szBuffer[0x10000] = { 0 };
    HANDLE hTraceFile;
private:
	DWORD OnLoadDllDEbugEvent();//��ʾDLL
	VOID ResumeBtCode(DWORD dwAddr,BYTE btOldCode); //��ԭԭ���Ĵ���
	VOID SetFAndDecEip(DWORD dwDecVal = 0);   //�����쳣
	DWORD  OnExceptionDebugEvent();// ��������¼�
    DWORD OnAccessViolation();
    void DecEip();
    //�ڴ����Ȩ���쳣 C05
	DWORD  OnBreakPoint();//�ϵ��쳣 c803
	DWORD OnSingleStep();//�����쳣 c804
    BhCommand m_bhCmd; //��������Ӳ���ϵ�
    vector<BMCommand> m_vctBmCmds;  //�����ڴ�ϵ���Ϣ
};

