#include <windows.h>
#include "child_reference.h"

__declspec(dllexport) unsigned long long child_rows[128][4];
__declspec(dllexport) DWORD child_pixels[80*60];
__declspec(dllexport) unsigned long long child_input[6][6];
static unsigned input_notifications;
static unsigned row,errors;
static DWORD hidden_pixels[80*60];
static const WCHAR klass[]=L"RavenChildFixture";

static LRESULT CALLBACK proc(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	// Windows made only to check ownership stay out of the recorded message rows.
	if (message==WM_NCCREATE && (LONG_PTR)((CREATESTRUCTW *)lparam)->lpCreateParams>=14) {
		SetWindowLongPtrW(window,GWLP_USERDATA,(LONG_PTR)((CREATESTRUCTW *)lparam)->lpCreateParams);
		return DefWindowProcW(window,message,wparam,lparam);
	}
	if (GetWindowLongPtrW(window,GWLP_USERDATA)>=14) return DefWindowProcW(window,message,wparam,lparam);
	if (message==WM_NCCREATE) {
		CREATESTRUCTW *create=(CREATESTRUCTW *)lparam;
		SetWindowLongPtrW(window,GWLP_USERDATA,(LONG_PTR)create->lpCreateParams);
		if ((LONG_PTR)create->lpCreateParams==12 && (!create->hwndParent || create->hMenu!=(HMENU)101 || create->x!=5 || create->y!=6)) ++errors;
		if ((LONG_PTR)create->lpCreateParams==13 && (!create->hwndParent || create->hMenu!=(HMENU)102 || create->x!=-3 || create->y!=4 || create->dwExStyle!=WS_EX_NOPARENTNOTIFY)) ++errors;
	}
	if (message==WM_PARENTNOTIFY && LOWORD(wparam)>=WM_MOUSEFIRST) {
		if (GetWindowLongPtrW(window,GWLP_USERDATA)!=11 || wparam!=WM_LBUTTONDOWN || lparam!=(20|(8<<16))) ++errors;
		++input_notifications;return DefWindowProcW(window,message,wparam,lparam);
	}
	if (message==WM_LBUTTONDOWN || message==WM_LBUTTONUP || message==WM_LBUTTONDBLCLK) return 0;
	if (message==WM_NCCREATE || message==WM_NCCALCSIZE || message==WM_CREATE || message==WM_SIZE || message==WM_MOVE ||
		message==WM_PARENTNOTIFY || message==WM_DESTROY || message==WM_NCDESTROY) {
		unsigned long long fields[4]={(unsigned long long)GetWindowLongPtrW(window,GWLP_USERDATA),message,wparam,
			message==WM_PARENTNOTIFY ? (unsigned long long)GetWindowLongPtrW((HWND)lparam,GWLP_USERDATA) :
			message==WM_SIZE || message==WM_MOVE ? (unsigned long long)lparam : 0};
		if (row>=128) ++errors;
		else for(unsigned j=0;j<4;++j)child_rows[row][j]=fields[j];
		++row;
	}
	if (message==WM_USER+1) return 37;
	return DefWindowProcW(window,message,wparam,lparam);
}

static int geometry(HWND window,int x,int y,int width,int height)
{
	RECT outer={0},client={0};POINT origin={0};
	return GetWindowRect(window,&outer) && GetClientRect(window,&client) && ClientToScreen(window,&origin) &&
		outer.left==x && outer.top==y && outer.right==x+width && outer.bottom==y+height &&
		!client.left && !client.top && client.right==width && client.bottom==height && origin.x==x && origin.y==y;
}

int raven_entry(void)
{
	HINSTANCE instance=GetModuleHandleW(NULL);
	WNDCLASSW wc={0};wc.lpfnWndProc=proc;wc.hInstance=instance;wc.lpszClassName=klass;
#ifdef CHILD_INPUT
	wc.style=CS_DBLCLKS;
#endif
	if (!RegisterClassW(&wc)) return 1;
	HWND parent=CreateWindowExW(0,klass,L"child surface",WS_POPUP,100,200,80,60,NULL,NULL,instance,(void *)11);
	HWND child=CreateWindowExW(0,klass,L"child",WS_CHILD|WS_VISIBLE,5,6,20,15,parent,(HMENU)101,instance,(void *)12);
	HWND grandchild=CreateWindowExW(WS_EX_NOPARENTNOTIFY,klass,L"grandchild",WS_CHILD|WS_VISIBLE,-3,4,8,7,child,(HMENU)102,instance,(void *)13);
	if (!parent || !child || !grandchild || errors) return 2;
	if (!geometry(parent,100,200,80,60) || !geometry(child,105,206,20,15) || !geometry(grandchild,102,210,8,7)) return 3;
	{
		HWND popup=CreateWindowExW(0,klass,L"owned popup",WS_POPUP,0,0,10,10,parent,NULL,instance,(void *)14);
		HWND overlapped=CreateWindowExW(0,klass,L"owned overlapped",WS_OVERLAPPED,0,0,10,10,parent,NULL,instance,(void *)15);
		int ok=popup && overlapped && GetParent(popup)==parent && GetWindow(popup,GW_OWNER)==parent && !GetParent(overlapped) && GetWindow(overlapped,GW_OWNER)==parent;
		if (popup) DestroyWindow(popup);
		if (overlapped) DestroyWindow(overlapped);
		if (!ok) return 13;
	}
	if (GetParent(parent) || GetParent(child)!=parent || GetParent(grandchild)!=child || !IsChild(parent,grandchild) ||
		IsChild(child,child) || IsChild(grandchild,parent) || GetDlgItem(parent,101)!=child || GetDlgItem(parent,102) ||
		GetDlgItem(child,102)!=grandchild || GetDlgCtrlID(grandchild)!=102 || GetMenu(child)!=(HMENU)101 || GetMenu(grandchild)!=(HMENU)102 || GetMenu(parent) || GetWindowLongPtrW(child,GWLP_ID)!=101 ||
		GetWindowLongPtrW(child,GWLP_HWNDPARENT)!=(LONG_PTR)parent || GetWindowLongW(grandchild,GWL_EXSTYLE)!=WS_EX_NOPARENTNOTIFY) return 4;
	if (IsWindowVisible(parent) || IsWindowVisible(child) || IsWindowVisible(grandchild)) return 5;
	ShowWindow(parent,SW_SHOW);
	if (!IsWindowVisible(parent) || !IsWindowVisible(child) || !IsWindowVisible(grandchild)) return 6;
	POINT point={0};MapWindowPoints(grandchild,parent,&point,1);if(point.x!=2 || point.y!=10) return 7;
	HDC parent_dc=GetDC(parent),child_dc=GetDC(child),grandchild_dc=GetDC(grandchild);
	HBRUSH base=CreateSolidBrush(RGB(16,32,48)),red=CreateSolidBrush(RGB(200,40,20)),green=CreateSolidBrush(RGB(4,180,60));
	RECT rect={-100,-100,200,200};
	if (!parent_dc || !child_dc || !grandchild_dc || !base || !red || !green ||
		!FillRect(parent_dc,&rect,base) || !FillRect(child_dc,&rect,red) || !FillRect(grandchild_dc,&rect,green)) return 8;
	BITMAPINFO info={0};info.bmiHeader.biSize=sizeof(info.bmiHeader);info.bmiHeader.biWidth=80;info.bmiHeader.biHeight=-60;
	info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;
	HDC memory=CreateCompatibleDC(parent_dc);DWORD *pixels=0;
	HBITMAP bitmap=CreateDIBSection(memory,&info,0,(void **)&pixels,NULL,0);HGDIOBJ old=SelectObject(memory,bitmap);
	if (!memory || !bitmap || !old || !BitBlt(memory,0,0,80,60,parent_dc,0,0,SRCCOPY)) return 9;
	for (unsigned y=0;y<60;++y)for(unsigned x=0;x<80;++x) {
		DWORD expected=x>=5 && x<25 && y>=6 && y<21 ? 0x00c82814 : 0x00102030;
		if (x>=5 && x<10 && y>=10 && y<17) expected=0x0004b43c;
		child_pixels[y*80+x]=pixels[y*80+x];if(pixels[y*80+x]!=expected) return 10;
	}
	LOGFONTW definition={0};definition.lfHeight=-12;definition.lfWeight=400;definition.lfQuality=NONANTIALIASED_QUALITY;
	const WCHAR face[]=L"Liberation Sans";for(unsigned i=0;i<sizeof(face)/sizeof(face[0]);++i)definition.lfFaceName[i]=face[i];
	HFONT font=CreateFontIndirectW(&definition);HGDIOBJ old_font=SelectObject(child_dc,font);
	if (!font || !old_font || !SetBkMode(child_dc,TRANSPARENT) || SetTextColor(child_dc,RGB(240,240,200))==CLR_INVALID ||
		!TextOutW(child_dc,1,1,L"Hi",2) || SelectObject(child_dc,old_font)!=font ||
		!BitBlt(memory,0,0,80,60,parent_dc,0,0,SRCCOPY)) return 18;
	unsigned long long digest=14695981039346656037ULL;
	for(unsigned i=0;i<80*60;++i) {
		child_pixels[i]=pixels[i];
		for(unsigned c=0;c<4;++c){digest^=(pixels[i]>>(c*8)) & 255U;digest*=1099511628211ULL;}
	}
#ifndef CHILD_ORACLE
	if (digest!=child_pixel_reference) return 19;
#endif
	ShowWindow(child,SW_HIDE);
	if (IsWindowVisible(child) || IsWindowVisible(grandchild) || !BitBlt(memory,0,0,80,60,parent_dc,0,0,SRCCOPY)) return 20;
	for(unsigned i=0;i<80*60;++i)hidden_pixels[i]=pixels[i];
	HDC hidden=GetDC(grandchild);
	if (!hidden || !FillRect(child_dc,&rect,green) || !FillRect(grandchild_dc,&rect,green) || !FillRect(hidden,&rect,green) ||
		!ReleaseDC(grandchild,hidden) || !BitBlt(memory,0,0,80,60,parent_dc,0,0,SRCCOPY)) return 21;
	for(unsigned i=0;i<80*60;++i)if(hidden_pixels[i]!=pixels[i])return 22;
	ShowWindow(child,SW_SHOW);
	RECT marker={19,14,20,15};
	if (!IsWindowVisible(grandchild) || !FillRect(child_dc,&marker,green) || !BitBlt(memory,0,0,80,60,parent_dc,0,0,SRCCOPY) || pixels[20*80+24]!=0x0004b43c ||
		!FillRect(child_dc,&marker,red) || !BitBlt(memory,0,0,80,60,parent_dc,0,0,SRCCOPY)) return 23;
	if (!FillRect(parent_dc,&rect,base) || !FillRect(child_dc,&rect,red) || !FillRect(grandchild_dc,&rect,green) ||
		!SelectObject(child_dc,font) || !TextOutW(child_dc,1,1,L"Hi",2) || SelectObject(child_dc,old_font)!=font || !DeleteObject(font) ||
		!BitBlt(memory,0,0,80,60,parent_dc,0,0,SRCCOPY)) return 24;
	for(unsigned i=0;i<80*60;++i)if(child_pixels[i]!=pixels[i])return 28;
	if (SelectObject(memory,old)!=bitmap || !DeleteObject(bitmap) || !DeleteDC(memory) || !DeleteObject(base) || !DeleteObject(red) || !DeleteObject(green) ||
		!ReleaseDC(parent,parent_dc) || !ReleaseDC(child,child_dc) || !ReleaseDC(grandchild,grandchild_dc)) return 11;
	if (!PostMessageW(grandchild,WM_USER+1,17,19)) return 12;
	MSG message={0};
	if (!PeekMessageW(&message,parent,WM_USER+1,WM_USER+1,PM_REMOVE) || message.hwnd!=grandchild || message.wParam!=17 || message.lParam!=19 || DispatchMessageW(&message)!=37) return 13;

#ifdef CHILD_INPUT
	// A child moved to the desktop, as a drop-down list is, keeps no owner and shows where the program puts it on the screen.
	HWND drop=CreateWindowExW(WS_EX_NOPARENTNOTIFY|WS_EX_TOOLWINDOW,klass,L"drop",WS_CHILD,0,0,20,10,parent,NULL,instance,(void *)16);
	if (!drop || SetParent(drop,NULL)!=parent || GetWindow(drop,GW_OWNER)) return 30;
	if (!SetWindowPos(drop,HWND_TOPMOST,130,230,20,10,SWP_SHOWWINDOW|SWP_NOACTIVATE) || !UpdateWindow(drop)) return 31;
	// The press on the child after one on the grandchild stays a press; the next press on the child, at the same point and at once, is a
	// double click for a class with CS_DBLCLKS and sends no parent notification.
	for(unsigned i=0;i<6;++i) {
		if (GetMessageW(&message,parent,WM_LBUTTONDOWN,WM_LBUTTONDBLCLK)<=0) return 25;
		const unsigned long long expected_tag=i<2 ? 13 : 12,expected_position=i<2 ? (4|(1<<16)) : (15|(2<<16));
		child_input[i][0]=(unsigned long long)GetWindowLongPtrW(message.hwnd,GWLP_USERDATA);
		child_input[i][1]=message.message;child_input[i][2]=message.wParam;child_input[i][3]=message.lParam;
		child_input[i][4]=message.pt.x;child_input[i][5]=message.pt.y;
		if (child_input[i][0]!=expected_tag || message.message!=(i & 1 ? WM_LBUTTONUP : i==4 ? WM_LBUTTONDBLCLK : WM_LBUTTONDOWN) ||
			message.wParam!=(i & 1 ? 0 : MK_LBUTTON) || (unsigned long long)message.lParam!=expected_position ||
			message.pt.x!=(i<2 ? 106 : 120) || message.pt.y!=(i<2 ? 211 : 208)) return 26;
		DispatchMessageW(&message);
	}
	if (input_notifications!=1 || !DestroyWindow(drop)) return 27;
#endif
	SetFocus(parent);if(SetFocus(grandchild)!=parent || GetFocus()!=grandchild || GetActiveWindow()!=parent || SetFocus(parent)!=grandchild) return 14;
	if (!DestroyWindow(parent) || IsWindow(child) || IsWindow(grandchild) || errors || !UnregisterClassW(klass,instance)) return 15;
	if (row!=sizeof(child_reference)/sizeof(child_reference[0])) return 16;
	for(unsigned i=0;i<row;++i)for(unsigned j=0;j<4;++j)if(child_rows[i][j]!=child_reference[i][j])return 17;
	return 0;
}

#ifdef CHILD_ORACLE
#include <stdio.h>
int main(void)
{
	int result=raven_entry();printf("result=%d errors=%u rows=%u\n",result,errors,row);
	for(unsigned i=0;i<row && i<128;++i)printf("row=%u %llu,%llu,%llu,%llu\n",i,child_rows[i][0],child_rows[i][1],child_rows[i][2],child_rows[i][3]);
	FILE *input=fopen("wine-child-input.bin","wb");if(input){fwrite(child_input,1,sizeof(child_input),input);fclose(input);}
	FILE *file=fopen("wine-child-pixels.bin","wb");if(file){fwrite(child_pixels,1,sizeof(child_pixels),file);fclose(file);}return result;
}
#endif
