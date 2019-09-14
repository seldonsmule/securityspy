package securityspy

/* simple get sunrise/set info */

import (
        "fmt"
        "io"
        //"time"
        //"strings"
        //"strconv"
        "os"
        "bytes"
        //"io/ioutil"
        //"encoding/json"
        "encoding/base64"
        "encoding/json"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
        "github.com/seldonsmule/logmsg"
        "github.com/seldonsmule/restapi"

)

type SSConf struct {

  Url         string
  IdAndPasswd string
  AccessToken string
  ConfigFile  string
  Encrypted   bool

}
 
type SecuritySpy struct {

  Config       SSConf

  byteKey []byte

  mSystemInfoMap map[string]interface{}
  mServerMap map[string]interface{}

  amCameraMapArray []interface{}

}

// returns a new SecuritySpy and saves all the info into a reusable
// config file

func NewBuildConfigEncrypt(url string, authstring string, configfile string,
                           keystring string) *SecuritySpy{

  ss := internalBuildConfig(url, authstring, configfile)

  ss.byteKey = []byte(keystring)

  switch len(ss.byteKey) {

    case 16: 
      fallthrough
    case 24: 
      fallthrough
    case 32: 
            
    default:
      logmsg.Print(logmsg.Error, 
                   "Key must be of size 16, 24 or 32 not: ", len(ss.byteKey))
      return nil 

  }

  ss.Config.Url = ss.encrypt(ss.Config.Url)
  ss.Config.IdAndPasswd = ss.encrypt(ss.Config.IdAndPasswd)
  ss.Config.AccessToken = ss.encrypt(ss.Config.AccessToken)

  ss.Config.Encrypted = true

  ss.SaveConfig()

  return(ss)

}



func NewBuildConfig(url string, authstring string, 
                    configfile string) *SecuritySpy{

  ss := internalBuildConfig(url, authstring, configfile)

  ss.SaveConfig()

  return ss
}

func internalBuildConfig(url string, authstring string, 
                         configfile string) *SecuritySpy{

  ss := new(SecuritySpy)


  ss.Config.Url = url
  ss.Config.IdAndPasswd = authstring
  ss.Config.AccessToken = ss.createAuthToken(authstring)
  ss.Config.ConfigFile = configfile

  return ss
}

func New(configfile string) *SecuritySpy{

  ss := new(SecuritySpy)

  ss.ReadConfig(configfile)

  return ss

}

func NewEncrypt(configfile string, keystring string) *SecuritySpy{

  ss := new(SecuritySpy)

  ss.byteKey = []byte(keystring)

  switch len(ss.byteKey) {

    case 16: 
      fallthrough
    case 24: 
      fallthrough
    case 32: 
            
    default:
      logmsg.Print(logmsg.Error, 
                   "Key must be of size 16, 24 or 32 not: ", len(ss.byteKey))
      return nil 

  }

  ss.ReadConfig(configfile)

  return ss

}

// addapted from https://gist.github.com/manishtpatel/8222606
//
// encrypt string to base64 crypto using AES

func (pSS *SecuritySpy) encrypt(text string) string {

  // key := []byte(keyText)
  plaintext := []byte(text)

  block, err := aes.NewCipher(pSS.byteKey)
  if err != nil {
    fmt.Println("aes.NewCipher err: ", err)
    panic(err)
  }

  // The IV needs to be unique, but not secure. Therefore it's common to
  // include it at the beginning of the ciphertext.
  ciphertext := make([]byte, aes.BlockSize+len(plaintext))
  iv := ciphertext[:aes.BlockSize]
  if _, err := io.ReadFull(rand.Reader, iv); err != nil {
    panic(err)
  }

  stream := cipher.NewCFBEncrypter(block, iv)
  stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

  // convert to base64
  return base64.URLEncoding.EncodeToString(ciphertext)
}

// addapted from https://gist.github.com/manishtpatel/8222606
//

func (pSS *SecuritySpy) decrypt(cryptoText string) string {

  ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

  block, err := aes.NewCipher(pSS.byteKey)
  if err != nil {
    panic(err)
  }

  // The IV needs to be unique, but not secure. Therefore it's common to
  // include it at the beginning of the ciphertext.
  if len(ciphertext) < aes.BlockSize {
    panic("ciphertext too short")
  }
  iv := ciphertext[:aes.BlockSize]
  ciphertext = ciphertext[aes.BlockSize:]

  stream := cipher.NewCFBDecrypter(block, iv)

  // XORKeyStream can work in-place if the two arguments are the same.
  stream.XORKeyStream(ciphertext, ciphertext)

  return fmt.Sprintf("%s", ciphertext)
}

func (pSS *SecuritySpy) SaveConfig() {

  j, err := json.Marshal(pSS.Config)

  if(err != nil){
    fmt.Println(err)
    return
  }

//  fmt.Println(string(j))

  writeFile, err := os.Create(pSS.Config.ConfigFile)

  if err != nil {
     logmsg.Print(logmsg.Error,"Unable to write config: ", err)
     fmt.Println("Unable to write config: ", err)
     return
  }
  defer writeFile.Close()

  writeFile.Write(j)
  //os.Stdout.Write(j)
  writeFile.Close()


}

func (pSS *SecuritySpy) ReadConfig(configfile string) {


  file, err := os.Open(configfile) // For read access.

  if err != nil {
     logmsg.Print(logmsg.Error,"Unable to config config: ", err," ",  configfile)
     fmt.Println("Unable to read config: ", err)
     return
     panic(err)
  }

  defer file.Close()

  data := make([]byte, 500)

  count, err := file.Read(data)

  if err != nil {
     logmsg.Print(logmsg.Error,"Unable to read config: ", err, count)
     fmt.Println("Unable to read config: ", err)
     return
  }

  err = json.NewDecoder(bytes.NewReader(data)).Decode(&pSS.Config)

  if err != nil {
     logmsg.Print(logmsg.Error,"Unable to decode config: ", err)
     fmt.Println("Unable to decode config: ", err)
     return
  }

}

func Version() string{

  return "0.1.a"
}

func (pSS *SecuritySpy) GetSystemInfo() bool{

  url := fmt.Sprintf("%s/++systemInfo", pSS.GetUrl())

  r := restapi.NewGetXML("systeminfo", url, true)

  r.SetBasicAccessToken(pSS.GetAccessToken())

  restapi.TurnOffCertValidation()

  if(r.Send()){

    //r.Dump()

  }else{
    
    logmsg.Print(logmsg.Error, "Call to security spy failed")
    return false
  }
  

/*
  fmt.Println("--------------------------")
  fmt.Printf("system[%s]\n", r.GetValue("system"))
  fmt.Println("--------------------------")
*/

//  fmt.Printf("system Type: %T\n", r.GetValue("system"))


  pSS.mSystemInfoMap = restapi.CastMap(r.GetValue("system"))
  pSS.mServerMap = restapi.CastMap(pSS.mSystemInfoMap["server"])
//  fmt.Printf("pSS.mSystemInfoMap Type: %T\n", pSS.mSystemInfoMap)
/*

  fmt.Println("--------------------------")
*/

  for k, v := range pSS.mSystemInfoMap {
    //fmt.Println(k, "=", v)
    if(k == "cameralist"){

/*
      fmt.Println("found cameralist")
      fmt.Println(v)
      fmt.Printf("v Type: %T\n", v)
*/

      // doing this strange test.  If you do not have the right level
      // of permissionsn (security spy login), the cameralist is
      // empty and you get a string not a map
      //
      // i am sure there is fancier ways of testing

      _, ok := v.(string)
      if(ok){
        fmt.Println("string no map!! ")
        pSS.amCameraMapArray = nil
        return true
      }

      mList := restapi.CastMap(v)

      //for k1, v1 := range mList {
      for _, v1 := range mList {
       
        pSS.amCameraMapArray = restapi.CastArray(v1)

      }


    }
  }

  return true
  
}

func (pSS *SecuritySpy) GetNumberOfCameras() int {

  return len(pSS.amCameraMapArray)

}


func (pSS *SecuritySpy) GetCameraMap(index int) map[string]interface{} {

  if(index > pSS.GetNumberOfCameras()){
    return nil
  }

  m := pSS.amCameraMapArray[index]

  return restapi.CastMap(m)
}

func (pSS *SecuritySpy) GetCameraValue(index int, value string) string {

  if(index > pSS.GetNumberOfCameras()){
    return "outofrange"
  }

  m := pSS.GetCameraMap(index)


  return restapi.CastString(m[value])
}

func (pSS *SecuritySpy) GetServerValue(value string) string {

  return restapi.CastString(pSS.mServerMap[value])
}

func (pSS *SecuritySpy) DumpCameraInfo(){

  fmt.Printf("Version[%s]\n", pSS.GetServerValue("version"))
  fmt.Printf("IP1[%s]\n", pSS.GetServerValue("ip1"))
  fmt.Printf("IP2[%s]\n", pSS.GetServerValue("ip2"))
  fmt.Printf("Http Port[%s]\n", pSS.GetServerValue("http-port"))
  fmt.Printf("Https Port[%s]\n", pSS.GetServerValue("https-port"))

  fmt.Printf("Number of Cameras[%d]\n", pSS.GetNumberOfCameras())

  if(pSS.GetNumberOfCameras() == 0){
    fmt.Printf("\tDo you have permssions to see the camera list??\n")
  }

  for i:=0; i < pSS.GetNumberOfCameras(); i++ {
            
    fmt.Printf("Num[%s] Name[%s] Address[%s] Connected[%s] Mode[%s] Motion[%s] Continuous[%s] Action[%s]\n",
                          pSS.GetCameraValue(i, "number"),
                          pSS.GetCameraValue(i, "name"),
                          pSS.GetCameraValue(i, "address"),
                          pSS.GetCameraValue(i, "connected"),
                          pSS.GetCameraValue(i, "mode"),
                          pSS.GetCameraValue(i, "mode-m"),
                          pSS.GetCameraValue(i, "mode-c"),
                          pSS.GetCameraValue(i, "mode-c") )

    fmt.Printf("    Preset1[%s] Preset2[%s] Preset3[%s] Preset4[%s]\n", 
                          pSS.GetCameraValue(i, "preset-name-1"),
                          pSS.GetCameraValue(i, "preset-name-2"),
                          pSS.GetCameraValue(i, "preset-name-3"),
                          pSS.GetCameraValue(i, "preset-name-4"))

    fmt.Printf("    Preset5[%s] Preset6[%s] Preset7[%s] Preset8[%s]\n", 
                          pSS.GetCameraValue(i, "preset-name-5"),
                          pSS.GetCameraValue(i, "preset-name-6"),
                          pSS.GetCameraValue(i, "preset-name-7"),
                          pSS.GetCameraValue(i, "preset-name-8"))

    fmt.Println()
  }
 
}


func (pSS *SecuritySpy) PresetPTZ(cameraNum int, presetNum int) bool{

  const presetStart = 11

  ssPresetParm := presetStart + presetNum

  url := fmt.Sprintf("%s/++ptz/command?cameraNum=%d&command=%d",
                     pSS.GetUrl(),
                     cameraNum,
                     ssPresetParm)


  logmsg.Print(logmsg.Info,"ptz url: ", url)

  r := restapi.NewGetXML("Server", url, false)

  r.SetBasicAccessToken(pSS.GetAccessToken())

  restapi.TurnOffCertValidation()

//r.DebugOn()


  if(r.Send()){

    //r.Dump()

  }else{
    
    logmsg.Print(logmsg.Error, "Call to security spy failed")
    return false
  }

  return true

}

func (pSS *SecuritySpy) createAuthToken(authString string) string{

  //fmt.Println(authString)
  sEnc := base64.StdEncoding.EncodeToString([]byte(authString))
  //fmt.Println(sEnc)

  return(sEnc)

}

func (pSS *SecuritySpy) decodeAuthToken(authString string) string{

  sDec, _ := base64.StdEncoding.DecodeString(authString)
  stringValue := string(sDec)

  return(stringValue)

}

func (pSS *SecuritySpy) GetIdAndPasswd() string {

  if(pSS.Config.Encrypted){
    return(pSS.decrypt(pSS.Config.IdAndPasswd))
  }

  return(pSS.Config.IdAndPasswd)

}
func (pSS *SecuritySpy) GetAccessToken() string {

  if(pSS.Config.Encrypted){
    return(pSS.decrypt(pSS.Config.AccessToken))
  }

  return(pSS.Config.AccessToken)

}

func (pSS *SecuritySpy) GetUrl() string {

  if(pSS.Config.Encrypted){
    return(pSS.decrypt(pSS.Config.Url))
  }

  return(pSS.Config.Url)

}

func (pSS *SecuritySpy) DumpConfig() {

  fmt.Println("Version: ", Version())
  fmt.Println("Url: ", pSS.GetUrl())
  fmt.Println("IdAndPass: ", pSS.GetIdAndPasswd())
  fmt.Println("AccessToken: ", pSS.GetAccessToken())
  fmt.Println("ConfigFile: ", pSS.Config.ConfigFile)
  fmt.Println("Encrypted: ", pSS.Config.Encrypted)
}

