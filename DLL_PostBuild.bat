cd %1
echo %1
move %3\%2.lib libs\
move %3\%2.exp libs\
echo %3\IHF_EnableSEH %3\%2.dll
%3\IHF_EnableSEH %3\%2.dll