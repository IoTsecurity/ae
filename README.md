ae
==

演示操作步骤
Auth Server IP：192.168.115.33		NVR IP：192.168.115.224
Client IP：192.168.115.42			Camera IP：192.168.115.40

直接观看视频
NVR：
$ cd /home/yaoyao/test_ffmpeg
$ ./run_ffserver.sh
$ ./run_ffmpeg.sh

Client: [vlc]rtsp://192.168.115.224:5454/live.h264

证书签发
Auth Server:
$ cd /home/lsc/git/ca/Debug/
$ ./ca

NVR:
$ cd /home/yaoyao/user/Debug/
$ ./user 192.168.115.33

WAI认证过程
Auth Server:
$ cd /home/lsc/git/asu/Debug/
$ ./asu

NVR:
$ cd /home/yaoyao/test_ffmpeg/ae/Debug
$ ./ae 192.168.115.33

Camera:
# cd /opt/yaoyao/asue_arm/
# ./vmcert.sh	（重置证书）
# ./asue 192.168.115.224

Client: [vlc]rtsp://192.168.115.224:5454/live.h264
