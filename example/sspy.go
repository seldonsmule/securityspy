package main

import (
       "fmt"
       "os"
       "strconv"
       "github.com/seldonsmule/securityspy"
       "github.com/seldonsmule/logmsg"
)

func help(){

  fmt.Println("sspy configfile [options]\n")
  fmt.Println("buildconfig url userid:password - Base64 encodes and saves userid and passwo rd\n")
  fmt.Println("info - show config file info \n")
  fmt.Println("systeminfo - show systeminfo\n")
  fmt.Println("preset cameranum presetnum - move to preset PTZ location\n")
  fmt.Println("help - Display this\n")


}

const EncryptKey = "example key 1234"

func main(){

  //ConfigFile := "ss.conf"

  fmt.Println("SecuritySpy demo")


  logfile := fmt.Sprintf("ss.log")

  logmsg.SetLogLevel(logmsg.Debug03)

  logmsg.SetLogFile(logfile)

  args := os.Args;

  if(len(args) >=3){ // being used for other reasons than moving the camera

    ConfigFile := args[1] 

    switch args[2]{

      case "buildconfig":
        //securityspy.NewBuildConfig(args[3], args[4], ConfigFile) 
        ss := securityspy.NewBuildConfigEncrypt(args[3], args[4], ConfigFile, EncryptKey) 
        ss.DumpConfig()

      case "preset":
        ss := securityspy.NewEncrypt(ConfigFile, EncryptKey)
        if(len(args) != 5){
           help()
        }else{
          fmt.Printf("camnum[%s] presetnum[%s]\n", args[3], args[4])
          cam, _ :=strconv.Atoi(args[3])
          preset, _ :=strconv.Atoi(args[4])
          ss.PresetPTZ(cam, preset)
        }


      case "info":
        ss := securityspy.NewEncrypt(ConfigFile, EncryptKey)
        ss.DumpConfig()
        

      case "tokendecoded":
        ss := securityspy.NewEncrypt(ConfigFile, EncryptKey)
        fmt.Println("Token: ", ss.GetAccessToken())

      case "systeminfo":
        ss := securityspy.NewEncrypt(ConfigFile, EncryptKey)

        if(ss.GetSystemInfo()){
          fmt.Println("Success")
          ss.DumpCameraInfo()

          fmt.Println("Url: ", ss.GetUrl())
          fmt.Println("IdAndPasswd: ", ss.GetIdAndPasswd())
          fmt.Println("AccessToken: ", ss.GetAccessToken())


        }else{
          fmt.Println("Get System Info failed - see log")
        }



      default:
        help()

    }

    os.Exit(0)

  }

  help()

}
