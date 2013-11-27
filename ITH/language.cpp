/*  Copyright (C) 2010-2012  kaosu (qiupf2000@gmail.com)
 *  This file is part of the Interactive Text Hooker.

 *  Interactive Text Hooker is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.

 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
const wchar_t* Warning=L"Warning!";
//command.cpp
const wchar_t* ErrorSyntax=L"Syntax error";
//inject.cpp
const wchar_t* ErrorRemoteThread=L"Can't create remote thread.";
const wchar_t* ErrorOpenProcess=L"Can't open process.";
const wchar_t* ErrorNoProcess=L"Process not found";
const wchar_t* SelfAttach=L"Please do not attach to ITH.exe";
const wchar_t* AlreadyAttach=L"Process already attached.";
const wchar_t* FormatInject=L"Inject process %d. Module base %.8X";
//main.cpp
const wchar_t* NotAdmin=L"Can't enable SeDebugPrevilege. ITH might malfunction.\r\n\
Please run ITH as administrator or turn off UAC.";
//pipe.cpp
const wchar_t* ErrorCreatePipe=L"Can't create text pipe or too many instance.";
const wchar_t* FormatDetach=L"Process %d detached.";
const wchar_t* ErrorCmdQueueFull=L"Command queue full.";
const wchar_t* ErrorNoAttach=L"No process attached.";

//profile.cpp
const wchar_t* ErrorMonitor=L"Can't monitor process.";
//utility.cpp
const wchar_t* InitMessage=L"Copyright (C) 2010-2012  kaosu (qiupf2000@gmail.com)\r\n\
Source code <https://code.google.com/p/interactive-text-hooker/>\r\n\
General discussion <https://groups.google.com/forum/?fromgroups#!forum/interactive-text-hooker>";
const wchar_t* BackgroundMsg=L"If you feel tired about the pure white background,\r\n\
put your favorite picture in ITH folder and name it 'background.bmp'\r\n";
const wchar_t* ErrorLinkExist=L"Link exist.";
const wchar_t* ErrorCylicLink=L"Link failed. No cyclic link allowed.";
const wchar_t* FormatLink=L"Link from thread%.4x to thread%.4x.";
const wchar_t* ErrorLink=L"Link failed. Source or/and destination thread not found.";
const wchar_t* ErrorDeleteCombo=L"Error delete from combo.";

//window.cpp
const wchar_t* ClassName=L"ITH";
const wchar_t* ClassNameAdmin=L"ITH (Administrator)";
const wchar_t* ErrorNotSplit=L"Need to enable split first!";
const wchar_t* ErrorNotModule=L"Need to enable module first!";
//Main window buttons
const wchar_t* ButtonTitleProcess=L"Process";
const wchar_t* ButtonTitleThread=L"Thread";
const wchar_t* ButtonTitleHook=L"Hook";
const wchar_t* ButtonTitleProfile=L"Profile";
const wchar_t* ButtonTitleOption=L"Option";
const wchar_t* ButtonTitleClear=L"Clear";
const wchar_t* ButtonTitleSave=L"Save";
const wchar_t* ButtonTitleTop=L"Top";
//Hook window
const wchar_t* SpecialHook=L"Special hook, no AGTH equivalent.";
//Process window
const wchar_t* TabTitlePID=L"PID";
const wchar_t* TabTitleMemory=L"Memory";
const wchar_t* TabTitleName=L"Name";
const wchar_t* TabTitleTID=L"TID";
const wchar_t* TabTitleStart=L"Start";
const wchar_t* TabTitleModule=L"Module";
const wchar_t* TabTitleState=L"State";
const wchar_t* SuccessAttach=L"Attach ITH to process successfully.";
const wchar_t* FailAttach=L"Failed to attach ITH to process.";
const wchar_t* SuccessDetach=L"ITH detach from process.";
const wchar_t* FailDetach=L"Detach failed.";
//Profile window
const wchar_t* ProfileExist=L"Profile already exists.";
const wchar_t* SuccessAddProfile=L"Profile added.";
const wchar_t* FailAddProfile=L"Fail to add profile";
const wchar_t* TabTitleNumber=L"No.";
const wchar_t* NoFile=L"Can't find file.";
const wchar_t* PathDismatch=L"Process name dismatch, continue?";
const wchar_t* SuccessImportProfile=L"Import profile success";
//const wchar_t* SuccessAddProfile=L"Profile added.";