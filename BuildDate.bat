@echo off
SET _result=%DATE:/=.%
echo const wchar_t* build_date=L"%_result%"; >%1%\include\ITH\version.h
@echo on
echo %_result%