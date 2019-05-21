using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Data.Common;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Linq;
using System.Xml;
using System.Xml.Linq;
using Org.BouncyCastle;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1;


namespace WindowsFormsApplication1
{
    public class ZJJXJZDll
    {

        public string strUrl = "http://101.37.162.154/visitortest/web";//（测试主机地址） 

        #region//定义民族
        public static readonly string[][]Nation = new string[][]
         {

           new string[]{"汉","1"} ,
           new string[]{"蒙古","2"} ,
           new string[]{"回","3"} , 
           new string[]{"藏","4"} ,
           new string[]{"维吾尔","5"} ,
           new string[]{"苗","6"} ,
           new string[]{"彝","7"} ,
           new string[]{"壮","8"} ,
           new string[]{"布依","9"} ,
           new string[]{"朝鲜","10"} ,
           new string[]{"满","11"} ,
           new string[]{"侗","12"} ,
           new string[]{"瑶","13"} ,
           new string[]{"白","14"} ,
           new string[]{"土家","15"} ,
           new string[]{"哈尼","16"} ,
           new string[]{"哈萨克","17"} ,
           new string[]{"傣","18"} ,
           new string[]{"黎","19"} ,
           new string[]{"傈僳","20"} ,
           new string[]{"佤","21"} ,
           new string[]{"畲","22"} ,
           new string[]{"高山","23"} ,
           new string[]{"拉祜","24"} ,
           new string[]{"水","25"} ,
           new string[]{"东乡","26"} ,
           new string[]{"纳西","27"} ,
           new string[]{"景颇","28"} ,
           new string[]{"柯尔克孜","29"} ,
           new string[]{"土","30"} ,
           new string[]{"达斡尔","31"} ,
           new string[]{"仫佬","32"} ,
           new string[]{"羌","33"} ,
           new string[]{"布朗","34"} ,
           new string[]{"撒拉","35"} ,
           new string[]{"毛南","36"} ,
           new string[]{"仡佬","37"} ,
           new string[]{"锡伯","38"} ,
           new string[]{"阿昌","39"} ,
           new string[]{"普米","40"} ,
           new string[]{"塔吉克","41"} ,
           new string[]{"怒","42"} ,
           new string[]{"乌孜别克","43"} ,
           new string[]{"俄罗斯","44"} ,
           new string[]{"鄂温克","45"} ,
           new string[]{"德昂","46"} ,
           new string[]{"保安","47"} ,
           new string[]{"裕固","48"} ,
           new string[]{"京","49"} ,
           new string[]{"塔塔尔","50"} ,
           new string[]{"独龙","51"} ,
           new string[]{"鄂伦春","52"} ,
           new string[]{"赫哲","53"} ,
           new string[]{"门巴","54"} ,
           new string[]{"珞巴","55"} ,
           new string[]{"基诺","56"} ,
           new string[]{"穿青人","59"} ,
           new string[]{"亻革家人","60"} ,
           new string[]{"其他","97"} ,
           new string[]{"外国血统中国籍","98"} ,
           new string[]{"不详","99"}  

         };
        #endregion

        #region//民族汉字转数字 
        public string NationToDigit(string para_strNationName)
        {
            try
            {
                if (para_strNationName == null || para_strNationName=="")
                {
                    return "99";
                }
                int i = 0;
                for (; i < Nation.Length; i++)
                {
                    if (para_strNationName == Nation[i][0].ToString().Trim())
                    {
                        break;
                    }
                }
                return Nation[i][1];
            }
            catch
            {
                return "99";
            }
        }
        #endregion

        #region//性别汉字转数字
        public string SexToDigit(string para_strSexName)
        {
            try
            {
                if (para_strSexName == "男")
                {
                    return "1";
                }
                else  if (para_strSexName == "女")
                {
                    return "2";
                }
                else if (para_strSexName == "未知性别")
                {
                    return "0";
                }
                else
                {
                    return "9";//未说明性别
                }
          
            }
            catch
            {
                return "9";
            }
        }
        #endregion

        #region//MD5加密（支持中文加密）
        /// <summary>
        /// ASP MD5加密算法
        /// </summary>
        /// <param name="md5str">要加密的字符串</param>
        /// <param name="type">16还是32位加密</param>
        /// <returns>Asp md5加密结果</returns>
        public string _md5(string str)
        {
            var md5Csp = new MD5CryptoServiceProvider();
            byte[] md5Source = Encoding.UTF8.GetBytes(str);
            byte[] md5Out = md5Csp.ComputeHash(md5Source);
            string pwd = "";
            for (int i = 0; i < md5Out.Length; i++)
            {
                pwd += md5Out[i].ToString("x2");
            }
            return pwd;
        }
        /// <summary>
        /// MD5加密（支持中文加密）
        /// </summary>
        /// <param name="para_strData">要加密的内容</param>
        /// <returns>GetMD5</returns>
        public  string GetMD5(string para_strData)
        {
            try
            {
                System.Security.Cryptography.MD5CryptoServiceProvider md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();
                byte[] bytValue, bytHash;
                bytValue = System.Text.Encoding.UTF8.GetBytes(para_strData);
                bytHash = md5.ComputeHash(bytValue);
                md5.Clear();
                string sTemp = "";
                for (int i = 0; i < bytHash.Length; i++)
                {
                    sTemp += bytHash[i].ToString("X").PadLeft(2, '0');
                }
                return sTemp.ToLower();
            }
            catch
            {
                return "";
            }
        }
        public string GetMd5Str32(string str)
        {
            MD5CryptoServiceProvider md5Hasher = new MD5CryptoServiceProvider();
            char[] temp = str.ToCharArray();
            byte[] buf = new byte[temp.Length];
            for (int i = 0; i < temp.Length; i++)
            {
                buf[i] = (byte)temp[i];
            }
            byte[] data = md5Hasher.ComputeHash(buf);
            StringBuilder sBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }
            return sBuilder.ToString();
        }
        #endregion
        #region//RSA加密（支持中文加密）
        /// <summary>
        /// generate private key and public key arr[0] for private key arr[1] for public key
        /// </summary>
        /// <returns>GenerateKeys</returns>
        public string[] GenerateKeys()
        {
            string[] sKeys = new String[2];
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            sKeys[0] = rsa.ToXmlString(true);
            sKeys[1] = rsa.ToXmlString(false);
            return sKeys;
        }
        public string sPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCTHQzHvD9Pg2liL4y616ihifDMm7xXC5YdDhgsf1+sgWgGW8X0MeTBEJnpj4O4g5Q1Tuzrq+CIdBkiPW9xmM81o6jBO5fuCq5pMT2qcOpy6/2T142+Af2XCPu0NJgefkzi8l8XlYc6V0HrNyXCJUJb25GB+zW0PnPjwU1/cStbHwIDAQAB";
        /// <summary>
        /// RSA Encrypt
        /// </summary>
        /// <param name="sSource" >Source string</param>
        /// <param name="sPublicKey" >public key</param>
        /// <returns>GetRSA</returns>
        /*public StringBuilder GetRSA(string sSource, string sPublicKey)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            string plaintext = sSource;
            rsa.FromXmlString(sPublicKey);
            byte[] cipherbytes;
            byte[] byteEn = rsa.Encrypt(Encoding.UTF8.GetBytes("a"), false);
            cipherbytes = rsa.Encrypt(Encoding.UTF8.GetBytes(plaintext), false);

            StringBuilder sbString = new StringBuilder();
            for (int i = 0; i < cipherbytes.Length; i++)
            {
                sbString.Append(cipherbytes[i] + ",");
            }
            return sbString;
        }*/
        /// <summary>
        /// 把java的公钥转换成.net的xml格式
        /// </summary>
        /// <param name="publicJavaKey">java提供的第三方公钥</param>
        /// <returns></returns>
        //public string ConvertToXmlPublicJavaKey(string publicJavaKey)
        //{
        //    RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicJavaKey));
        //    string xmlpublicKey = string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
        //      Convert.ToBase64String(publicKeyParam.Modulus.ToByteArrayUnsigned()),
        //      Convert.ToBase64String(publicKeyParam.Exponent.ToByteArrayUnsigned()));
        //    return xmlpublicKey;
        //}

        /// <summary>
        /// 创建RSA公钥私钥
        /// </summary>
        public void CreateRSAKey()
        {
            //设置[公钥私钥]文件路径
            string privateKeyPath = @"d:\\PrivateKey.xml";
            string publicKeyPath = @"d:\\PublicKey.xml";
            //创建RSA对象
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            //生成RSA[公钥私钥]
            string privateKey = rsa.ToXmlString(true);
            string publicKey = rsa.ToXmlString(false);
            // string publicKey = sPublicKey;
            //将密钥写入指定路径
            File.WriteAllText(privateKeyPath, privateKey);//文件内包含公钥和私钥
            File.WriteAllText(publicKeyPath, publicKey);//文件内只包含公钥

        }
        /// <summary>
        /// java公钥转C#所需公钥
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public string RSAPublicKeyJava2DotNet(string publicKey)
        {
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
                Convert.ToBase64String(publicKeyParam.Modulus.ToByteArrayUnsigned()),
                Convert.ToBase64String(publicKeyParam.Exponent.ToByteArrayUnsigned()));
        }

        /// <summary>
        /// 使用RSA实现加密
        /// </summary>
        /// <param name="data">加密数据</param>
        /// <returns></returns>
        public string RSAEncrypt(string data)
        {
            //C#默认只能使用[公钥]进行加密(想使用[公钥解密]可使用第三方组件BouncyCastle来实现)
            //string publicKeyPath = @"D://PublicKey.xml";
            //string publicKey = File.ReadAllText(publicKeyPath);
            //string publicKey = "<RSAKeyValue><Modulus>MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCTHQzHvD9Pg2liL4y616ihifDMm7xXC5YdDhgsf1+sgWgGW8X0MeTBEJnpj4O4g5Q1Tuzrq+CIdBkiPW9xmM81o6jBO5fuCq5pMT2qcOpy6/2T142+Af2XCPu0NJgefkzi8l8XlYc6V0HrNyXCJUJb25GB+zW0PnPjwU1/cStbHwID</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
            string publicKey = RSAPublicKeyJava2DotNet(sPublicKey);
            // string publicKey = sPublicKey;
            //创建RSA对象并载入[公钥]
            RSACryptoServiceProvider rsaPublic = new RSACryptoServiceProvider();
            rsaPublic.FromXmlString(publicKey);
            //对数据进行加密
            byte[] publicValue = rsaPublic.Encrypt(Encoding.UTF8.GetBytes(data), false);
            string publicStr = Convert.ToBase64String(publicValue);//使用Base64将byte转换为string
            return publicStr;
        }
        #endregion

        #region//图片地址转Base64
        /// <summary>
        /// 图片转Base64
        /// </summary>
        /// <param name="para_strPath">图片路径</param>
        /// <returns>ImgBase64</returns>

        public string ImgBase64(string para_strPath)
        {
            //try
            //{
            //    Image img;
            //    if (!File.Exists(para_strPath))
            //    {
            //        throw new Exception("文件不存在!");
            //    }
            //    img = Image.FromFile(para_strPath);
            //    MemoryStream ms = new MemoryStream();
            //    string file_etx = Path.GetExtension(para_strPath).ToLower();
            //    switch (file_etx)
            //    {
            //        case ".jpg":
            //            img.Save(ms, ImageFormat.Jpeg);
            //            break;
            //        case ".png":
            //            img.Save(ms, ImageFormat.Png);
            //            break;
            //        case ".gif":
            //            img.Save(ms, ImageFormat.Gif);
            //            break;
            //        case ".bmp":
            //            img.Save(ms, ImageFormat.Bmp);
            //            break;
            //        default:
            //            img.Save(ms, ImageFormat.Jpeg);
            //            break;
            //    }
            //    return Convert.ToBase64String(ms.ToArray());
            //}
            //catch
            //{
            //    return "";
            //}

            System.IO.FileStream fs = System.IO.File.OpenRead(para_strPath);
            System.IO.BinaryReader br = new System.IO.BinaryReader(fs);
            string base64String = Convert.ToBase64String(br.ReadBytes((int)fs.Length));
            br.Close();
            fs.Close();
            return base64String;
        }
        #endregion

        #region//接口转入统一方式为HTTP POST
        /// <summary>
        /// 接口转入统一方式为HTTP POST
        /// </summary>
        /// <param name="para_strPath">HTTP地址</param>
        /// <param name="para_strPostData">请求的数据</param>
        /// <returns>HttpPost</returns>
        public  string HttpPost(string para_strUrl, string para_strPostData)
        {
            string ret = string.Empty;
            try
            {
                byte[] byteArray = Encoding.UTF8.GetBytes(para_strPostData); //转化为UTF8
                HttpWebRequest webReq = null;

                webReq = (HttpWebRequest)WebRequest.Create(new Uri(para_strUrl));
                webReq.Method = "POST";
                webReq.ContentType = "application/x-www-form-urlencoded";
                webReq.ContentLength = byteArray.Length;
                Stream newStream = webReq.GetRequestStream();
                newStream.Write(byteArray, 0, byteArray.Length);//写入参数
                newStream.Close();
                HttpWebResponse response = (HttpWebResponse)webReq.GetResponse();
                StreamReader sr = new StreamReader(response.GetResponseStream(), Encoding.UTF8);
                ret = sr.ReadToEnd();
                sr.Close();
                response.Close();
                newStream.Close();
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    if (response != null)
                    {
                        int errorcode = (int)response.StatusCode;
                        ret = errorcode + "," + ex.Message;
                    }
                    else
                    {
                        // no http status code available
                        ret = ex.Message;
                    }
                }
                else
                {
                    // no http status code available
                    ret = ex.Message;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return ret;
        }
        #endregion

        #region// 设备基本数据上传：说明：此接口可用于新增和修改设备信息，当设备号已存在，即进行修改
        /// <summary>
        /// 接口转入统一方式为HTTP POST
        /// </summary>
        /// <param name="para_strdeviceno">设备号</param>
        /// <param name="para_strdwmc">单位名称</param>
        /// <param name="para_strpcsdm">派出所代码</param>
        /// <param name="para_strlxdh">单位联系电话</param>
        /// <param name="para_strlxry">单位联系人员,值可以为空</param>
        /// <param name="para_strlat">纬度,截至到小数点后6位,比如：30.826932</param>
        /// <param name="para_strlng">经度,截至到小数点后6位，比如：120.880123</param>
        /// <param name="para_strflag">厂商标志(标志位：公司名英文缩写) </param>

        /// <returns>UpLoadMachineInfToServer</returns>
        public string UpLoadMachineInfToServer(string para_strdeviceno, string para_strdwmc, string para_strpcsdm, string para_strlxdh, string para_strlxry, string para_strlat, string para_strlng, string para_strflag)
        {
            try
            {
                string strPostData = "deviceno=" + para_strdeviceno + "&dwmc=" + para_strdwmc + "&pcsdm=" + para_strpcsdm + "&lxdh=" + para_strlxdh + "&lxry=" + para_strlxry + "&lat=" + para_strlat + "&lng=" + para_strlng + "&flag=" + para_strflag;
                string strSign = GetMD5(strPostData + "&key=yudianedutest");
                strPostData += "&sign=" + strSign;
                string result = HttpPost(strUrl + @"/Rest/visitor/senddeviceno", strPostData);
                return result;//0表示上传成功  1002:sign拼接有错误(有可能字段顺序不对)  1004:PostData值为空
            }
            catch (Exception exp)
            {
                return exp.ToString();
            }
        }
        #endregion

        #region// 访客登记数据上传：说明：此方法用于新增访客数据，不能进行修改，图片请尽量上传现场照片
        //注1：日期数据库格式为date，参数传递时请以字符串形式进行传递，csrq的格式为yyyymmdd

        /// <summary>
        /// 接口转入统一方式为HTTP POST
        /// </summary>
        /// <param name="para_strdeviceno">设备号</param>
        /// <param name="para_strv_id">终端到访记录ID,主键ID,wg标识</param>
        /// <param name="para_strv_name">访客姓名</param>
        /// <param name="para_strv_sex">性别  0：未知性别 1：男性 2：女性 9：未说明性别</param>
        /// <param name="para_strv_cardID">访客身份证</param>
        /// <param name="para_strv_birth_date">出生日期,yyyymmdd</param>
        /// <param name="para_strv_nation">民族,民族数字对照格式表</param>
        /// <param name="para_strv_address">住址</param>
        /// <param name="para_strv_phone">电话号码,值可以为空</param>
        /// <param name="para_strv_headpic_url">访客头像【身份证头像】,base64</param>
        /// <param name="para_strv_image_url">现场拍照图片,base64</param>
        /// <param name="para_strv_time">来访时间,20170609140000</param>
        /// <param name="para_strv_leave_time">离开时间,20170609150000,值可以为空</param>
        /// <param name="para_strv_department">被访部门,软件部,值可以为空</param>
        /// <param name="para_strv_people">被访人员,王五,值可以为空</param>
        /// <param name="para_strv_carno">车牌号,浙F12345,值可以为空</param>
        /// <param name="para_strv_desc">拜访理由,值可以为空</param>
       
        /// <returns>UpLoadMachineInfToServer</returns>
        public string UpLoadVisitorInfToServer(string para_strdeviceno, string para_strv_id, string para_strv_name, string para_strv_sex, string para_strv_cardID, string para_strv_birth_date, string para_strv_nation, string para_strv_address,
             string para_strv_phone, string para_strv_headpic_url, string para_strv_image_url, string para_strv_time, string para_strv_leave_time, string para_strv_department, string para_strv_people, string para_strv_carno,string para_strv_desc)

        {
            try
            {
                string strPostData = "deviceno=" + para_strdeviceno + "&v_id=" + para_strv_id + "&v_name=" + para_strv_name + "&v_sex=" + SexToDigit(para_strv_sex).ToString() + "&v_cardID=" + para_strv_cardID;
                strPostData += "&v_birth_date=" + Convert.ToDateTime(para_strv_birth_date).ToString("yyyyMMdd") + "&v_nation=" + NationToDigit(para_strv_nation) + "&v_address=" + para_strv_address;
                strPostData += "&v_phone=" + para_strv_phone;
                strPostData += "&v_headpic_url=" + ImgBase64(para_strv_headpic_url);
                strPostData += "&v_image_url=" + ImgBase64(para_strv_image_url);
                strPostData += "&v_time=" + Convert.ToDateTime(para_strv_time).ToString("yyyyMMddHHmmss") + "&v_leave_time=" + Convert.ToDateTime(para_strv_leave_time).ToString("yyyyMMddHHmmss");
                strPostData += "&v_department=" + para_strv_department + "&v_people=" + para_strv_people + "&v_carno=" + para_strv_carno + "&v_desc=" + para_strv_desc;
                string strSign = GetMD5(strPostData + "&key=yudianedutest");
                strPostData += "&sign=" + strSign;

                string result = "";

                result = HttpPost(strUrl + @"/Rest/visitor/sendvisitorinfos", strPostData);
                Console.WriteLine(result);

                return result;//0表示上传成功  1002:sign拼接有错误(有可能字段顺序不对)  1004:PostData值为空

            }
            catch (Exception exp)
            {
                return exp.ToString();
            }
        }
        #endregion

        #region// 访客离开时间上传：说明：此接口可用于新增和修改设备信息，当设备号已存在，即进行修改
        /// <summary>
        /// 接口转入统一方式为HTTP POST
        /// </summary>
        /// <param name="para_strdeviceno">设备号</param>
        /// <param name="para_strv_id">终端到访记录ID,主键ID,wg标识</param>
        /// <param name="para_strv_leavetime">离开时间</param>

        /// <returns>UpLoadMachineInfToServer</returns>
        public string UpLoadsendleavetimeToServer(string para_strdeviceno, string para_strv_id, string para_strv_leavetime)
        {
            try
            {
                string strPostData = "deviceno=" + para_strdeviceno + "&v_id=" + para_strv_id + "&v_leavetime=" + Convert.ToDateTime(para_strv_leavetime).ToString("yyyyMMddHHmmss");

                string strSign = GetMD5(strPostData + "&key=yudianedutest");
                strPostData += "&sign=" + strSign;
                string result = HttpPost(strUrl + @"/Rest/visitor/sendleavetime", strPostData);
                return result;//0表示上传成功  10023:sign拼接有错误(有可能字段顺序不对)  10024:PostData值为空
            }
            catch (Exception exp)
            {
                return exp.ToString();
            }
        }
        #endregion

        #region// 信息采集接口：说明：流动人口信息采集接口
        //注1：日期数据库格式为date，参数传递时请以字符串形式进行传递，csrq的格式为yyyymmdd

        /// <summary>
        /// 接口转入统一方式为HTTP POST
        /// </summary>
        /*
        <body>
        <accessNumber>账号</accessNumber>
        <name> 姓名  RSA加密密钥见文档</name>必填
        <sex>性别</sex>
        <nation>民族（文字）</nation>
        <credentialsNumber>证件号 RSA加密 密钥见文档</credentialsNumber>必填
        <credentialsType>证件类型  证件类型(1居民身份证、2军官证、3武警警官证、4士兵证、5护照、6港澳同胞回乡证、7台湾居民来往大陆通行证、8外国人居留证、9其他)(不能为空)</credentialsType>必填
        <address>户籍地址</address>
        <issuingAuthority>签发机关</issuingAuthority>
        <expiryDate>有效期</expiryDate>
        <company>工作单位</company>
        <tempAddress>暂住地</tempAddress>
        <contactInformation>联系方式（可以是手机或座机）</contactInformation>
        <collectionSite>采集点</collectionSite>必填
        <collectionMode>采集模式(1:公安窗口、2:警务通、3:其他窗口)(不能为空)</collectionMode>必填
        <collectionType>采集类型(0:自动读取、1:人员录入)(不能为空)</collectionType>
        <credentialsPhotoType>证件照片类型(1:身份证人脸照、2:证件照、3:模版照)(不能为空)</credentialsPhotoType>必填
        <credentialsPhoto>证件照 BASE64值</credentialsPhoto>必填
        <photograph>现场照 BASE64值</photograph>必填
        <operator>操作人员(提交信息的那个人员的登录名)</operator>
        <submissionType>提交类型(0:正常提交、1:强制提交)(不能为空)</submissionType>必填
        <personnelID>人员信息ID</personnelID>
        <credentialsPhotoID>证件照片ID</credentialsPhotoID>
        <photographID>现场照片ID</photographID>
        <personnelType>人员类型</personnelType>
        <community>居委会编号（代码）</community>必填
        <brithday>出生日期 yyyy-MM-dd</brithday>
        <pwd>密码</pwd>
        </body>
        */

        /// <returns>UpLoadMachineInfToServer</returns>
        public string UploadInfoToServer(string accessNumber, string name, string sex, string nation, string credentialsNumber, string credentialsType, string address,
            string issuingAuthority, string expiryDate, string company, string tempAddress, string contactInformation, string collectionSite, string collectionMode,
            string collectionType, string credentialsPhotoType, string credentialsPhoto, string photograph, string _operator, string submissionType, string personnelID,
            string credentialsPhotoID, string photographID, string personnelType, string community, string brithday, string pwd)
        {
            try
            {
                string _accessNumber = "accessNumber=" + accessNumber;
                string info = "name=" + RSAEncrypt(name) + "&sex=" + sex + "&nation=" + nation + "&credentialsNumber=" + RSAEncrypt(credentialsNumber);
                info += "&credentialsType=" + credentialsType + "&address=" + address + "&issuingAuthority=" + issuingAuthority;
                info += "&expiryDate=" + expiryDate + "&company=" + company + "&tempAddress=" + tempAddress + "&contactInformation=" + contactInformation;
                info += "&collectionSite=" + collectionSite + "&collectionMode=" + collectionMode + "&collectionType=" + collectionType + "&credentialsPhotoType=" + credentialsPhotoType;
                info += "&credentialsPhoto=" + ImgBase64(credentialsPhoto);
                info += "&photograph=" + ImgBase64(photograph);
                info += "&operator=" + _operator + "&submissionType=" + submissionType + "&personnelID=" + personnelID + "&credentialsPhotoID=" + credentialsPhotoID;
                info += "&photographID=" + photographID + "&personnelType=" + personnelType;
                info += "&community=" + community + "&brithday=" + Convert.ToDateTime(brithday).ToString("yyyy-MM-dd");
                string _pwd = "pwd=" + pwd;
                //string md5 = GetMD5(_accessNumber + "&" + info + "&" + _pwd);
                string md5 = GetMD5(accessNumber + info + _pwd);
                string resultdata = _accessNumber + "&md5=" + md5 + "&" + info;
                

                string result = "";

                result = HttpPost("http://211.138.112.188:9555/FloatingPopulationExtranet/api/ldrkCollection.html", resultdata);
                Console.WriteLine(result);

                return result;// 100 成功,101 参数错误,102 非法接入用户

            }
            catch (Exception exp)
            {
                return exp.ToString();
            }
        }
        public string UploadInfoToServer2(string accessNumber,string pwd)
        {
            //UploadInfoToServer3();
            try
            {
                string _accessNumber = "accessNumber=" + accessNumber;
                string infoPath = @"D://info1.xml";
                string infoKey = File.ReadAllText(infoPath).Replace("\r\n", "").Replace("  ","");
                string info = "&info="+infoKey;
                string _pwd = "&pwd=" + pwd;
                string md5Text = accessNumber + infoKey + pwd;
                //string md5Text = accessNumber + "+" + infoKey + "+" + pwd;
                string md5 = _md5(md5Text);
                //MessageBox.Show("md5:"+md5);
                //string md5 = GetMD5(md5Text);
                string resultdata = _accessNumber + "&md5=" + md5 + info;
                //string resultdata = accessNumber + md5 + infoKey;

                string result = "";
                //result = HttpPost("http://211.138.112.188:9555/FloatingPopulationExtranet/api/ldrkCollection.html", resultdata);
                result = HttpPost("https://wxqwer.mynatapp.cc/api/ldrkCollection.html", resultdata);
                // Console.WriteLine(result);
                return result;// 100 成功,101 参数错误,102 非法接入用户,103 MD5 校验出错,104 解析 xml 出错,110 必填项缺失
            }
            catch (Exception exp)
            {
                return exp.ToString();
            }
        }
        public void UploadInfoToServer3() {
            XDocument xdoc = new XDocument();
            XDeclaration xdec = new XDeclaration("1.0", "utf-8", "no");
            xdoc.Declaration = xdec;

            //创建根节点
            XElement rootElement = new XElement("body");
            rootElement.SetElementValue("name", RSAEncrypt("林祺泰"));
            rootElement.SetElementValue("credentialsNumber", RSAEncrypt("330327199207250810"));
            rootElement.SetElementValue("credentialsType", "1");
            rootElement.SetElementValue("collectionSite", "动车站");
            rootElement.SetElementValue("collectionMode", "2");
            rootElement.SetElementValue("collectionType", "0");
            rootElement.SetElementValue("credentialsPhotoType", "2");
            rootElement.SetElementValue("credentialsPhoto", "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");
            rootElement.SetElementValue("photograph", "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCACgAHgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDNooor7k+ECiiigAoopkkscMZklkWNB/E5wKNhpXH0VlyeI9Hjbab+In/ZyR+gqRNc0qRwi6hblj0BfH86y9tTenMvvNHQqrXlf3M0KKRSGXcpDD1ByKWtTIKKKKACiiigAooooAKKKKACiiuJ8U+ITM7afZyYiXiaRf4j6D2rDEYiNCHNI6MNh54ifJEuaz4wS2drfTlWWQcNM3KqfYd/5Vx15fXN9MZLqZ5X/wBo8D6DoKgxnp+VBUD3PrXzVfF1Kz956dj6fD4SlQXurXv1EJz1oJzTTRmue502LVpfXVk++2nkiP8Ast1/Cuu0jxkkpWHUlEbHgTqPl/Edvwrh80ua3oYqrRd4vTt0OavhKVdWmte/U9jVldQysGVhkEHIIpa8+8M6+2nzraXDk2khwM/8sz6j29a9Br6TC4mOIhzLfqfNYrCyw8+V7dGFFFFdJyhRRRQAUUUUAYnifVDp2mFIziefKKR2Hc150qk/U810Hiu5+1a28fVLdQg+vU1kRxjYzEYOa+YzCs6tZrotD6nL6KpUF3epDtG046Dqe5NNZT1P/wCqrWwZAFMePJxXAd5SI5xRjirXkEjOKUQHpjqKBlUDNLt61aS33Gl+zkrn04NAimK9A8I6sbyzNnK2ZYB8pJ5ZP/rVw5ixJj1q7oly+n6xBIDhd21voeDXVgq7o1U+j3OTG0FWotdVsen0UUV9YfJBRRRQAUZA5PQcmimTZ8iXHXY38qTdkNK7seZXUoluZZevmOWP4kmoMksAO3ajnI74q3ZWM19dxwQKWd+vtk18ZKXVn20Y7JDYoGkdEUcmtBNCvp3HlReY2MkLz3r1fRfDXhvSNPjbVRA88cW6QyHO0dzj0rbtE8P3TFtLa1kMeCfJxlf8K5ZVuqOyOHWzZ4xN4P16CGOQ6bNtYZ+77VWbw1rUa720y52hN2fLNfSFr88YBO4U27L7CNxx7Go9u0rl/V4nzU9jdQuqvbOjMcHcuKhvbO606ULLGVVh8rdjXvGoXfhzR5Fk1Uwq75K703E460+6/wCEf1WAQeTCVljDrG8e0lT0IBFHt3vYn6unpfU+ek2vKGf1LfpTVwzAj+Gun8b+FzoN1HPagmyuCQmf4G9K5YfumXJ+9XRCSkro5pwcXZnpumTG40y2lb7zRjP1HFWqztCGNDtD6pn8ya0a+1otunFvsj4mskqkku7CiiitDIKQgMCp6EYpaKAPLZojBPJG3BRip/A16R8MtGkPnanIq+XIvlx5HOc81x/iey+yam8q/cnHmD2Pcf59a9Y+HoUeE7DbjG1s/Xca+JxlN05OD7n3WAmqqU12Ojh0S1IfdEG3jD5/iHpUNvoljpZ/0K0jt4w27bENoJ9/Wt6HlAAKSaIJEzyEBVGc159tLHq6lKxkZOW9aszMJMEc81QtWa4YsqkL2zSzySWsgYqSvfFQ3oFrjLjR7K8lLXVrFOu7diVd2D7Z6VLNpNsUGIlwOnFaUQWWJZIyCrDOae4GzkU7XQ1c4XxxpyXfhO7iZfmhXzUPoV/+tmvA5G+QeqnH619JeJii6LeF8bRC+fyNfPmmWYvtcggwdpk3t/ujk11YOLm+RdTgxslBc76HoOnQm30y1hIwUiUEe+Ks0UV97FcqSR8BKXM231CiiimSFFFFAGL4l043uneagzJBlseq9/8AGt74YagZNGmsyfmt5cj/AHWGf5g0QwSTyqkaFifbiq/h6xm8N+NHtZlCwX0Z8sjpuHzAflmvnM5hT5uaL16o+nyOpUS5ZLToz1q0cbVpdTHnWxjU89arWsg8setVL/UFgkCyuEU9zXzsmfTp3HRz30VyCnk+SF/1ZXBB/wB7PP5U2Wa+uJo5dyiLBBhCg7vqT0/Cqf8Aa1tglZCR3bBx+dMGsWyBR5pI/E1lJs2VOW9jotNHk2yxkjdyT+NSXDjFYllqiS3CrE28H2Nak7EjFNPQjVPU4r4g35tvDF1g4MmIx+Jrz3wppoigk1CQfvJiRH7J/wDXNdP8SmlvG07S7dS0s0pfaPbgfqabb6bc2lnFCbdh5SBTtGRkDmvcyONP2jlN7bHzufTnyKEFvuJRRRX1p8gFFFFAEtvbyXU4hiGXP6V02meFQzK1ywY91/hrotO0a2sIQsUa57t3NayQgAYGK+XxmazqNxp6L8T6nB5TCmlKpq/wMZ9Ijt4wI0XAOAAOg74rNvLGGZn86IExlXRj1Vh0xXWbBkfLxWdfwF4pCEwScLXk899z1uS2xn28u6JW5ANPmjWZSGAOaS8tjbW9iAMZypIHcjP+NRCQxjDjj1rmqLWx105O1yOO1a3VvLiBVutO+yNOoVotoHtV6G4iZRkgj61K1xHtOCAKh3sdCqPuV7eBLdMBRxTpZS3AGWPAAqtNc7n2x/MT6dqjiLrqFopb5pJNoHvg/wCFQnrYiV7XKsWlQz3r6hNErzEBEY87V9BWnBp5JZWBXPQ9RWjDbCK5nhPHzZA9jV5IkRcfrXXDRHFJczuznbjw/b3SbZYVI6BhwfzrktX8P3OlkyAGS37MOo+v+NenFCAxXHXimTwrPEUdc5HQjrXoYXH1cO9Hddjz8Vl9KutVZ9zx2iuj1/w6bMPd2o/cD70YH3ff6UV9Vh8TCvDngfK4jDToT5Jo9FWNQMmnjPYUPnHFPTlcY4r4NvU+9SHooKnK/jUcqLsIAGakCtjuB7VDMdsbHPNFxlfWLIz6bKkKgyRqJEx6jkfn0/GsWDy7m3SVeVcZFdXuEgjcf3ABjoTXHuP7L1mWyYFYJj50BPTn7y/gf50VVsyqT3RJ9hibkoDSGxiXogq7HhuRTmUZ56Vk0bJlWK3VATiqUkfn+IdJiVsbZzKceiqa05GwuBWfoQ+1+L5JRyLaEhfcnj/GpjH3kEnozbnBbWWKnjyxke+TVxFOOtRlNt5K2RkngE56cVZUHGe/vXS9DlQioFPOKcyKenFJgkYNHPQGlcdipLbK6MrJlTRV3ZxzRVxm0tDOVNN6jH+7UluQVPrTJF4xSR5U8Vh1NywRxjp+NQOvJyBU2R1JppwT1+tUhMjh2gmL+FfnA9PpVHX9KOoWwCf8fEZ3wv0w3p9DV2X91NG6Y5ODVtlDRAAn8a0teNmZp8sro4ywuTKm1wVkXhlPrWgdxHFVtZtmsb9bpMFJeWI/vd/z61JFdpJHncMiubZ8rOxNNXRBev5Nu5JwxHFXPCOn/ZLGa9lDCSc/KcchfWq1vaf2re/PnyE5wf4v/rV0d6/kQx2seAWI6dh15ranG2phVn0RGq7mD8jJ/CpRzgHtUStgU+NgWzjinJkRJlUYGRQ4AYEU/coFRlhWdy7CsSUPqKKiMuDgjiirTIZMVDDNNEfOe1IJMY5prTAEYNPkDnHlcU3gGlaVQMk81WnuUQct9cdaFBic0ST4wp7gg1bikUqVXkkdhnispZi6oxYOeuRwCKlllkhTZGSs2dzEHIUY6VolYhsdqPlzabdfa4isac5POFH8XH4mubt/DggmWU6lIyZyFdAUcfUV0MUbyWpillZ8nc2TnJqOS0VUYAt5RXO3sp/pVezW7Eqsloi1YzRSRnyx5cqfKVxgj3qFnZ7ou4BzggkdB6VHBavblZ1OZeA249R6U2SZBctIgIVuCp5207diVLuXVTccDvUvklelR2reYM4OKtEjGefrXPNHRFkBGTzSheakIB/GkVQMtiosVcimT5feipGxtINFWiGf/9k=");
            rootElement.SetElementValue("submissionType", "0");
            rootElement.SetElementValue("community", "12231231");
            rootElement.SetElementValue("brithday", "1992-07-25");
            xdoc.Add(rootElement);

            xdoc.Save(@"D://info.xml");
        }
        string info_template = "<body><name>_nameRSA</name><sex>_sex</sex><nation>_nation</nation><credentialsNumber>_credentialsNumberRSA</credentialsNumber><credentialsType>_credentialsType</credentialsType><address>_address</address><issuingAuthority>_issuingAuthority</issuingAuthority><expiryDate>_expiryDate</expiryDate><company>_company</company><tempAddress>_tempAddress</tempAddress><contactInformation>_contactInformation</contactInformation><collectionSite>_collectionSite</collectionSite><collectionMode>_collectionMode</collectionMode><collectionType>_collectionType</collectionType><credentialsPhotoType>_credentials_PhotoType</credentialsPhotoType><credentialsPhoto>_credentialsPhoto</credentialsPhoto><photograph>_photograph</photograph><operator>_operator</operator><submissionType>_submissionType</submissionType><personnelID>_personnelID</personnelID><credentialsPhotoID>_credentials_PhotoID</credentialsPhotoID><photographID>_photo_graphID</photographID><personnelType>_personnelType</personnelType><community>_community</community><brithday>_brithday</brithday></body>";
        public string UploadInfoToHLServer(PersonInfo personInfo)
        {
            string nameRSA = RSAEncrypt(personInfo.Name);
            string credentialsNumberRSA = RSAEncrypt(personInfo.CredentialsNumber);
            //UploadInfoToServer3();
            try
            {
                //string infoKey = "<body><name>JYKnZKNMbourZR99xI4EBFaFUGHiIaahJtYMVcfvyBEayAzySgmSTA /rTHzp3ybV377z69083Kv99/lfpripA vNn/L9CH0uHT5GUUAQzf4cJINHYBgW1SdQfRtg7QmFiyNvEYvFW6i7ByCsOyOE/imyaWmHitzVPgt6uXWZKVmANQu7CtAicfqvNgwY464g91jhZ44dn5GhaEMl3BOqTlc</name><sex>1</sex><nation>han</nation><credentialsNumber>AUAdr2Ktm8CBOiwodAnr7SAO9SwL/I/Y9NEru0CODba4d96tT6j/O0RKXfeqvaODi4WnZMBNle mr1aLiSb5WwEmWcogJTANFLFi YVvKUHJt g/cDye5tQEo9eQmpB7DviCH/iu3M uYaJCTdlyumzyB7FjN evEO3x8HwkWALws5oycSE8K1SVfsDMQJE0pENbpXzwDAP7eFeR10923lsK</credentialsNumber><credentialsType>9</credentialsType><address>111</address><issuingAuthority>123</issuingAuthority><expiryDate>1992-08-12</expiryDate><company>123</company><tempAddress>bhhj</tempAddress><contactInformation>66</contactInformation><collectionSite>sss</collectionSite><collectionMode>3</collectionMode><collectionType>1</collectionType>1<credentialsPhotoType>1</credentialsPhotoType><credentialsPhoto>/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCACgAHgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4 Tl5ufo6erx8vP09fb3 Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3 Pn6/9oADAMBAAIRAxEAPwD3 iiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiua8W NNO8KWLPMwlu2wI7dTySe59BQB0FxcwWkDz3EqRRIMs7tgD8a4fWPixoOnZW0El 47x/Kv5mvH/EXjDVfEUzyX90zQFspAhwifQf1NczJcsx9R7UAemal8Z9aeUmyht7ePPAK7zj3zWHL8UvFE53JqzofRY0A/lXCySEsf51EhO5hnlTQB6JafF/xRbEb7yKcA8rLEDn8Riuw0f45WskiR6xpzQgnBmt23AfVTz teEyEhlPr1pAzDPr0oA ydN1Ww1i0W70 7iuYG6PG2fz9KuV8heHPE p G9QW7065aJv4l6q49GHevorwP8AEPT/ABfD5D7bbU0GXty3De6eo9u1AHZ0UUUAFFFFABRRRQBieJ/Elr4Z0mS9uAGI4VM4yT0r5p8Qa3da1q813dP8zMWCjoAef8/QV1XxO8RvrfiOa0iOLSyOFAP336bj/SuGOJ1zxkcZoAY5Zz1GRUO3JzmpgCvynjHeqs9wUf5eB3FMAdASxH1FMXasu7sQKh84k5zwaaSSOOaQFiUKxBzwKYQPlx NRbj3PPpTk3MODQAKvz4qxBdT2V3Fc28rRTRkMjqcFSKrsWBzj60omBGGAoGfTvw28cL4u0gxXLKup2wAmX/novZx/I /1ruK TfB2vXHhnxFa6lC25I2xKmfvxnhh XP1Ar6vhlSeCOaNt0cihlPqCMikA iiimIKoa3d/YNDvrvODFAzD644q/XPeOS3/CF6mFOGMYUfiwFAHzZcSvcXM08hy8khdj71l2jMjOPcg1a3FVlBPzLJj9KqyuE5HG7k0wNHT9OudYfyrZNzn1OM/jUN/4b1e1cifTpwR3CEj9K6v4aGFo7qRyA3mgDuenavSru4lmh2Q74gB97yiSaxlNpm8aaaPnyDRNRmYhbGfj/AGDUh0q6ixutZgenKmvZDdvGxD3cjY6 ZEB/StZBHLbrKFVgR1AzWft2tkX9XXU8NGj37x7o7CRyemRgCq1xYalbRGSSzITvgZx VeuXqWUpdriWRY1ODsJA/OqsCaLJCRbs HJUEOMMfTk80vbN62H7CO1zx3zxnBXg9RSPGFbqQD0rq/EPh4JLK0KMPlLA7eP0rllBmtkI 8Tt/Kt4S5lc55x5XYdbS U4yePavqH4Y6/FrHgqxV5V 0Ww zupPJ29P0xXy15LBgD Ne//AAR0KOHR7jVZCzSPJ5cat0QYGSPc5qiT1qiiimIKyvEtq154fu4V6lcj8Dn latNkQSRsh6MMUAfJ2rxJHqt9FGwI81tv4GsK7YrECPcV3XjjSZNI8W3iSRhVLblIGAytyD/AJ9K5C6tdyMvH3u1AzrfhxcTPbylGSGIlUORjLDOeffINejyaJHdjzZppZOCAm/5Rn271wHwhnVftts3Zw2PUYr1G7srORSfIUE914/lXPN 8zrpr3UcM2hRaZMywTyl3fd8zZJ9vpV630mf yZDdtmSVyVPIx74rdtrC1glyIgHNaFxAht8EgN6GsXdpm0Uk0cLawFyI79xvjLIobgbSMY9DxWpbaNpkNp5MUcSx53Y3d/WtCW3WLO5Qyn IcipoLaEKGWKP8FFRzNqzK5V0OT1XShtkCO75Qqoj5xn1PQCvL54/st5NG N8bEEjvX0RIUNuQQOPWvAPFrAeKb4LgDeDx9BW1CWvKc9eOnMUo0V5jKTx2HvX0N8G7kS FZYf ecx4 tfOyyjyWA7HtXsHwYvJrWaZPMzBOQCh9cHkV1HIe4UUUUxBQTjrRSMiupVgCp6g0AeafFzSLO90uO NxHHcwjbtLAbkznPqSPT3NeHSODhRzkj9K j/FOg6O1qZZNPjeXBCszHAPbjPJ9q8D8TaXHpWtrbxuGyPMYAYCk9h9OOaADwFcmz8VMgOElBGK9tUllB7V886DqJtPFVoW2iOSYKTjpngV9A27jyVye1ctVe9c7KL92wvlZk35xjpWYmkw6fJPPFPKZ7qQM5kkLL AJwPwq1e35tIWZYjK3ZV6msK5uNUnBkYRgHoocDbWe60OiEW2Tw6bDYtOttuWOeQySDcWy5789K1LdiEwa5tZ9TtiCqxyjugbOa37WcvGpddrdxWL0epq4taE8zYiYDuK8K8Xsn/CQXGJFZixyo6j617jM4KMf4cV873jC 1m8uB0lnZgfbNbYdXk2cuJdo2G2ymV/lBOeuK9z Hnh26tbFNisC DjP3cHqK5X4ceDG1No3khPlvMpMjDgIpyce RX0LZadbafHst49oxjPeu1HCTxKyRKrOXIGCx70U imIKKKKAMvV7a5uICIsYH3Qi/OfoTwK8a8e D7y1tW1OWBLdCSCA292J9T/kV7zXOeO9MbVfB oQR58xYzIuO OcUAfJdxFhxtJDA8EV7R4O8SpruiIznF3BiOdfU9mH1Fec FNC/4SHUblGOEiiLgDqx9BXpOleCD4ahW7SbdFqC7gmMFCPT2IIrKtH3Lm1CVp2NtkaQfLz9apzaY0gy7hB6inJcy2rYkQsnqKSfVIG4LY tcWh6CvfQbHYtGoVH3AVMAYx8xqCK/jPCEn6UkjSzNz8i/rWTsXr1Mbxzrz6T4Zn z/6 ciBWH8AbqfrjNePWp2rwO2a9H JQA0CBQP8Al4X RrlPCOhTa54is9PiQsJGy3GcADJzXdhl7h5 Jfvn0l8N7aK38C6YYwMvHuPGCD7 9dZVHR7D zNKt7Pdu8pAucYq9XScwUUUUAFFFNd1RSzsFUdSTigB1MmjWaGSJvuupU/QiuZ1XxdDEZIbHEjqDmTt HrXJXGuXWoiwEtzIyCTLZbGWwcZ/GrcGouTO6GArSg5tWRyZ0C9 G2uyXUbwXkbll ykkNIp6YIziutt/EOo IwHvbGKygiAEMKMWIz1JP5cCnvAsshd13H1PWpFQRj5RiuKdRyViIUlF3G7Qcg1SuYEb AH61cLgHNRyMpHNYPY6EylBGqHhAKmfmmqyhulOLAmsTQw/E2jjV9N zbiDncD6EVv/CrTNE0fzZHudupOSm2YbTt9j0NMkTeORWdPa/NkDHNbU6zhoZVKKnqe2jpRXlGk INT0ohUnMkI/5ZyHI/D0rpbfx/bG78i6tJI8ruDo24e/FdlOtGenU5nhal7RVzsqKp2Gp2epReZaTrIB1A6j8KK1OeUXF2aszG1/xONPDR2oR5F4ZjyBXCahrt5fk bO7L6E/0qPVZjIJlJOd9ZqEmInv0rqSUdEfW4bA0qMU7XfclWV1lDE5xx9RUeDHJPCvZvMj/AM/Wmk/KPyqabjy5u44Y xob5kdrgrWOgs5xcwJKP4hyKmOAKzdIP7uSMfwtkD2NaIyOa8iUeVtM Zq03Cbj2K0q56VUdyGINajgFTVN4gx5rKSFEqF8dKkjBJzUy24J9aXbtOAKjlKuA6D3proGGcU4hs5NIRJjgfjVWAgZVUc1kXMm24eX0XArXljKxs8hwo/WsST95KB2zk104eGtzvwFLmnzdizp pXOntFLBIySKc7gaKrSfd nFFdtj0p4alN3nFMvXjF7iZT/AHjiqsRwwU9DwakuZCl9KrdN5qFm2zA/jWretzeOwsg2sR71YGJICpqGb5kDjvUls24MKI7tDa6j7G6a2mDHnHDe4rofODoCvIIzXMSKVfcO3X3q9Y3uxQjnK9jXJXpt 8jzMfhnP95DfqaZdunakHJp67ZFyDTSCK4WjyEx6YUUpbceAKYvSpEQUIT01FGPTNDfTFSIgzWfqV sIMaEF/5VtCDloiqUJVZcsSjqd1uPlg8L1qhGpALH7x6 1ABkbzGzgcjPc tOTlTXdCHKrH0lCkqUFFEZGRRT8cEUVaNGf//Z</credentialsPhoto><photograph>/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCACgAHgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4 Tl5ufo6erx8vP09fb3 Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3 Pn6/9oADAMBAAIRAxEAPwDNooor7k ECiiigAoopkkscMZklkWNB/E5wKNhpXH0VlyeI9Hjbab In/ZyR gqRNc0qRwi6hblj0BfH86y9tTenMvvNHQqrXlf3M0KKRSGXcpDD1ByKWtTIKKKKACiiigAooooAKKKKACiiuJ8U ITM7afZyYiXiaRf4j6D2rDEYiNCHNI6MNh54ifJEuaz4wS2drfTlWWQcNM3KqfYd/5Vx15fXN9MZLqZ5X/wBo8D6DoKgxnp VBUD3PrXzVfF1Kz956dj6fD4SlQXurXv1EJz1oJzTTRmue502LVpfXVk  2nkiP8Ast1/Cuu0jxkkpWHUlEbHgTqPl/Edvwrh80ua3oYqrRd4vTt0OavhKVdWmte/U9jVldQysGVhkEHIIpa8 8M6 2nzraXDk2khwM/8sz6j29a9Br6TC4mOIhzLfqfNYrCyw8 V7dGFFFFdJyhRRRQAUUUUAYnifVDp2mFIziefKKR2Hc150qk/U810Hiu5 1a28fVLdQg vU1kRxjYzEYOa YzCs6tZrotD6nL6KpUF3epDtG046Dqe5NNZT1P/wCqrWwZAFMePJxXAd5SI5xRjirXkEjOKUQHpjqKBlUDNLt61aS33Gl zkrn04NAimK9A8I6sbyzNnK2ZYB8pJ5ZP/rVw5ixJj1q7oly n6xBIDhd21voeDXVgq7o1U j3OTG0FWotdVsen0UUV9YfJBRRRQAUZA5PQcmimTZ8iXHXY38qTdkNK7seZXUoluZZevmOWP4kmoMksAO3ajnI74q3ZWM19dxwQKWd vtk18ZKXVn20Y7JDYoGkdEUcmtBNCvp3HlReY2MkLz3r1fRfDXhvSNPjbVRA88cW6QyHO0dzj0rbtE8P3TFtLa1kMeCfJxlf8K5ZVuqOyOHWzZ4xN4P16CGOQ6bNtYZ 77VWbw1rUa720y52hN2fLNfSFr88YBO4U27L7CNxx7Go9u0rl/V4nzU9jdQuqvbOjMcHcuKhvbO606ULLGVVh8rdjXvGoXfhzR5Fk1Uwq75K703E460 6/wCEf1WAQeTCVljDrG8e0lT0IBFHt3vYn6unpfU ek2vKGf1LfpTVwzAj Gun8b FzoN1HPagmyuCQmf4G9K5YfumXJ 9XRCSkro5pwcXZnpumTG40y2lb7zRjP1HFWqztCGNDtD6pn8ya0a 1otunFvsj4mskqkku7CiiitDIKQgMCp6EYpaKAPLZojBPJG3BRip/A16R8MtGkPnanIq XIvlx5HOc81x/iey yam8q/cnHmD2Pcf59a9Y HoUeE7DbjG1s/Xca JxlN05OD7n3WAmqqU12Ojh0S1IfdEG3jD5/iHpUNvoljpZ/0K0jt4w27bENoJ9/Wt6HlAAKSaIJEzyEBVGc159tLHq6lKxkZOW9aszMJMEc81QtWa4YsqkL2zSzySWsgYqSvfFQ3oFrjLjR7K8lLXVrFOu7diVd2D7Z6VLNpNsUGIlwOnFaUQWWJZIyCrDOae4GzkU7XQ1c4XxxpyXfhO7iZfmhXzUPoV/ tmvA5G QeqnH619JeJii6LeF8bRC fyNfPmmWYvtcggwdpk3t/ujk11YOLm RdTgxslBc76HoOnQm30y1hIwUiUEe Ks0UV97FcqSR8BKXM231CiiimSFFFFAGL4l043uneagzJBlseq9/8AGt74YagZNGmsyfmt5cj/AHWGf5g0QwSTyqkaFifbiq/h6xm8N NHtZlCwX0Z8sjpuHzAflmvnM5hT5uaL16o nyOpUS5ZLToz1q0cbVpdTHnWxjU89arWsg8setVL/UFgkCyuEU9zXzsmfTp3HRz30VyCnk SF/1ZXBB/wB7PP5U2Wa uJo5dyiLBBhCg7vqT0/Cqf8Aa1tglZCR3bBx dMGsWyBR5pI/E1lJs2VOW9jotNHk2yxkjdyT NSXDjFYllqiS3CrE28H2Nak7EjFNPQjVPU4r4g35tvDF1g4MmIx Jrz3wppoigk1CQfvJiRH7J/wDXNdP8SmlvG07S7dS0s0pfaPbgfqabb6bc2lnFCbdh5SBTtGRkDmvcyONP2jlN7bHzufTnyKEFvuJRRRX1p8gFFFFAEtvbyXU4hiGXP6V02meFQzK1ywY91/hrotO0a2sIQsUa57t3NayQgAYGK XxmazqNxp6L8T6nB5TCmlKpq/wMZ9Ijt4wI0XAOAAOg74rNvLGGZn86IExlXRj1Vh0xXWbBkfLxWdfwF4pCEwScLXk899z1uS2xn28u6JW5ANPmjWZSGAOaS8tjbW9iAMZypIHcjP NRCQxjDjj1rmqLWx105O1yOO1a3VvLiBVutO yNOoVotoHtV6G4iZRkgj61K1xHtOCAKh3sdCqPuV7eBLdMBRxTpZS3AGWPAAqtNc7n2x/MT6dqjiLrqFopb5pJNoHvg/wCFQnrYiV7XKsWlQz3r6hNErzEBEY87V9BWnBp5JZWBXPQ9RWjDbCK5nhPHzZA9jV5IkRcfrXXDRHFJczuznbjw/b3SbZYVI6BhwfzrktX8P3OlkyAGS37MOo v NenFCAxXHXimTwrPEUdc5HQjrXoYXH1cO9Hddjz8Vl9KutVZ9zx2iuj1/w6bMPd2o/cD70YH3ff6UV9Vh8TCvDngfK4jDToT5Jo9FWNQMmnjPYUPnHFPTlcY4r4NvU 9SHooKnK/jUcqLsIAGakCtjuB7VDMdsbHPNFxlfWLIz6bKkKgyRqJEx6jkfn0/GsWDy7m3SVeVcZFdXuEgjcf3ABjoTXHuP7L1mWyYFYJj50BPTn7y/gf50VVsyqT3RJ9hibkoDSGxiXogq7HhuRTmUZ56Vk0bJlWK3VATiqUkfn IdJiVsbZzKceiqa05GwuBWfoQ 1 L5JRyLaEhfcnj/GpjH3kEnozbnBbWWKnjyxke TVxFOOtRlNt5K2RkngE56cVZUHGe/vXS9DlQioFPOKcyKenFJgkYNHPQGlcdipLbK6MrJlTRV3ZxzRVxm0tDOVNN6jH 7UluQVPrTJF4xSR5U8Vh1NywRxjp NQOvJyBU2R1JppwT1 tUhMjh2gmL FfnA9PpVHX9KOoWwCf8fEZ3wv0w3p9DV2X91NG6Y5ODVtlDRAAn8a0teNmZp8sro4ywuTKm1wVkXhlPrWgdxHFVtZtmsb9bpMFJeWI/vd/z61JFdpJHncMiubZ8rOxNNXRBev5Nu5JwxHFXPCOn/ZLGa9lDCSc/KcchfWq1vaf2re/PnyE5wf4v/rV0d6/kQx2seAWI6dh15ranG2phVn0RGq7mD8jJ/CpRzgHtUStgU NgWzjinJkRJlUYGRQ4AYEU/coFRlhWdy7CsSUPqKKiMuDgjiirTIZMVDDNNEfOe1IJMY5prTAEYNPkDnHlcU3gGlaVQMk81WnuUQct9cdaFBic0ST4wp7gg1bikUqVXkkdhnispZi6oxYOeuRwCKlllkhTZGSs2dzEHIUY6VolYhsdqPlzabdfa4isac5POFH8XH4mubt/DggmWU6lIyZyFdAUcfUV0MUbyWpillZ8nc2TnJqOS0VUYAt5RXO3sp/pVezW7Eqsloi1YzRSRnyx5cqfKVxgj3qFnZ7ou4BzggkdB6VHBavblZ1OZeA249R6U2SZBctIgIVuCp5207diVLuXVTccDvUvklelR2reYM4OKtEjGefrXPNHRFkBGTzSheakIB/GkVQMtiosVcimT5feipGxtINFWiGf/9k=</photograph><operator>15700085065</operator><submissionType>0</submissionType><personnelID>1</personnelID><credentialsPhotoID>1</credentialsPhotoID><photographID>1</photographID><personnelType>1</personnelType><policestation>sss</policestation><community>330327001002</community><brithday>1980-01-01</brithday></body>";
                string infoStr = info_template;//传的接口参数用的，里面的+号需要替换成%2B
                infoStr = infoStr.Replace("_nameRSA", nameRSA.Replace("+", "%2B"));
                //infoStr = infoStr.Replace("_nameRSA", RSAEncrypt(personInfo.Name).Replace("+", " "));
                //infoStr = infoStr.Replace("_nameRSA", "JYKnZKNMbourZR99xI4EBFaFUGHiIaahJtYMVcfvyBEayAzySgmSTA /rTHzp3ybV377z69083Kv99/lfpripA vNn/L9CH0uHT5GUUAQzf4cJINHYBgW1SdQfRtg7QmFiyNvEYvFW6i7ByCsOyOE/imyaWmHitzVPgt6uXWZKVmANQu7CtAicfqvNgwY464g91jhZ44dn5GhaEMl3BOqTlc");
                infoStr = infoStr.Replace("_sex", personInfo.Sex);
                infoStr = infoStr.Replace("_nation", personInfo.Nation);
                infoStr = infoStr.Replace("_credentialsNumberRSA", credentialsNumberRSA.Replace("+", "%2B"));
                //infoStr = infoStr.Replace("_credentialsNumberRSA", RSAEncrypt(personInfo.CredentialsNumber).Replace("+", " "));//.Replace("+", " ")
                //infoStr = infoStr.Replace("_credentialsNumberRSA", "AUAdr2Ktm8CBOiwodAnr7SAO9SwL/I/Y9NEru0CODba4d96tT6j/O0RKXfeqvaODi4WnZMBNle mr1aLiSb5WwEmWcogJTANFLFi YVvKUHJt g/cDye5tQEo9eQmpB7DviCH/iu3M uYaJCTdlyumzyB7FjN evEO3x8HwkWALws5oycSE8K1SVfsDMQJE0pENbpXzwDAP7eFeR10923lsK");
                infoStr = infoStr.Replace("_credentialsType", personInfo.CredentialsType);
                infoStr = infoStr.Replace("_address", personInfo.Address);
                infoStr = infoStr.Replace("_issuingAuthority", personInfo.IssuingAuthority);
                infoStr = infoStr.Replace("_expiryDate", personInfo.ExpiryDate);
                infoStr = infoStr.Replace("_company", personInfo.Company);
                infoStr = infoStr.Replace("_tempAddress", personInfo.TempAddress);
                infoStr = infoStr.Replace("_contactInformation", personInfo.ContactInformation);
                infoStr = infoStr.Replace("_collectionSite", personInfo.CollectionSite);
                infoStr = infoStr.Replace("_collectionMode", personInfo.CollectionMode);
                infoStr = infoStr.Replace("_collectionType", personInfo.CollectionType);
                infoStr = infoStr.Replace("_credentials_PhotoType", personInfo.CredentialsPhotoType);
                infoStr = infoStr.Replace("_credentialsPhoto", ImgBase64(personInfo.CredentialsPhoto).Replace("+", "%2B"));
                infoStr = infoStr.Replace("_photograph", ImgBase64(personInfo.Photograph).Replace("+", "%2B"));
                infoStr = infoStr.Replace("_operator", personInfo._operator1);
                infoStr = infoStr.Replace("_submissionType", personInfo.SubmissionType);
                infoStr = infoStr.Replace("_personnelID", personInfo.PersonnelID);
                infoStr = infoStr.Replace("_credentials_PhotoID", personInfo.CredentialsPhotoID);
                infoStr = infoStr.Replace("_photo_graphID", personInfo.PhotographID);
                infoStr = infoStr.Replace("_personnelType", personInfo.PersonnelType);
                //infoStr = infoStr.Replace("_policestation", personInfo.Policestation);
                infoStr = infoStr.Replace("_community", personInfo.Community);
                infoStr = infoStr.Replace("_brithday", personInfo.Brithday);

                string infoStr1 = info_template;//md5加密用的
                infoStr1 = infoStr1.Replace("_nameRSA", nameRSA);
                //infoStr = infoStr.Replace("_nameRSA", RSAEncrypt(personInfo.Name).Replace("+", " "));
                //infoStr = infoStr.Replace("_nameRSA", "JYKnZKNMbourZR99xI4EBFaFUGHiIaahJtYMVcfvyBEayAzySgmSTA /rTHzp3ybV377z69083Kv99/lfpripA vNn/L9CH0uHT5GUUAQzf4cJINHYBgW1SdQfRtg7QmFiyNvEYvFW6i7ByCsOyOE/imyaWmHitzVPgt6uXWZKVmANQu7CtAicfqvNgwY464g91jhZ44dn5GhaEMl3BOqTlc");
                infoStr1 = infoStr1.Replace("_sex", personInfo.Sex);
                infoStr1 = infoStr1.Replace("_nation", personInfo.Nation);
                infoStr1 = infoStr1.Replace("_credentialsNumberRSA", credentialsNumberRSA);
                //infoStr = infoStr.Replace("_credentialsNumberRSA", RSAEncrypt(personInfo.CredentialsNumber).Replace("+", " "));//.Replace("+", " ")
                //infoStr = infoStr.Replace("_credentialsNumberRSA", "AUAdr2Ktm8CBOiwodAnr7SAO9SwL/I/Y9NEru0CODba4d96tT6j/O0RKXfeqvaODi4WnZMBNle mr1aLiSb5WwEmWcogJTANFLFi YVvKUHJt g/cDye5tQEo9eQmpB7DviCH/iu3M uYaJCTdlyumzyB7FjN evEO3x8HwkWALws5oycSE8K1SVfsDMQJE0pENbpXzwDAP7eFeR10923lsK");
                infoStr1 = infoStr1.Replace("_credentialsType", personInfo.CredentialsType);
                infoStr1 = infoStr1.Replace("_address", personInfo.Address);
                infoStr1 = infoStr1.Replace("_issuingAuthority", personInfo.IssuingAuthority);
                infoStr1 = infoStr1.Replace("_expiryDate", personInfo.ExpiryDate);
                infoStr1 = infoStr1.Replace("_company", personInfo.Company);
                infoStr1 = infoStr1.Replace("_tempAddress", personInfo.TempAddress);
                infoStr1 = infoStr1.Replace("_contactInformation", personInfo.ContactInformation);
                infoStr1 = infoStr1.Replace("_collectionSite", personInfo.CollectionSite);
                infoStr1 = infoStr1.Replace("_collectionMode", personInfo.CollectionMode);
                infoStr1 = infoStr1.Replace("_collectionType", personInfo.CollectionType);
                infoStr1 = infoStr1.Replace("_credentials_PhotoType", personInfo.CredentialsPhotoType);
                infoStr1 = infoStr1.Replace("_credentialsPhoto", ImgBase64(personInfo.CredentialsPhoto));
                infoStr1 = infoStr1.Replace("_photograph", ImgBase64(personInfo.Photograph));
                infoStr1 = infoStr1.Replace("_operator", personInfo._operator1);
                infoStr1 = infoStr1.Replace("_submissionType", personInfo.SubmissionType);
                infoStr1 = infoStr1.Replace("_personnelID", personInfo.PersonnelID);
                infoStr1 = infoStr1.Replace("_credentials_PhotoID", personInfo.CredentialsPhotoID);
                infoStr1 = infoStr1.Replace("_photo_graphID", personInfo.PhotographID);
                infoStr1 = infoStr1.Replace("_personnelType", personInfo.PersonnelType);
                //infoStr = infoStr.Replace("_policestation", personInfo.Policestation);
                infoStr1 = infoStr1.Replace("_community", personInfo.Community);
                infoStr1 = infoStr1.Replace("_brithday", personInfo.Brithday);

                //infoStr = "<body><name>JYKnZKNMbourZR99xI4EBFaFUGHiIaahJtYMVcfvyBEayAzySgmSTA /rTHzp3ybV377z69083Kv99/lfpripA vNn/L9CH0uHT5GUUAQzf4cJINHYBgW1SdQfRtg7QmFiyNvEYvFW6i7ByCsOyOE/imyaWmHitzVPgt6uXWZKVmANQu7CtAicfqvNgwY464g91jhZ44dn5GhaEMl3BOqTlc</name><sex>1</sex><nation>han</nation><credentialsNumber>AUAdr2Ktm8CBOiwodAnr7SAO9SwL/I/Y9NEru0CODba4d96tT6j/O0RKXfeqvaODi4WnZMBNle mr1aLiSb5WwEmWcogJTANFLFi YVvKUHJt g/cDye5tQEo9eQmpB7DviCH/iu3M uYaJCTdlyumzyB7FjN evEO3x8HwkWALws5oycSE8K1SVfsDMQJE0pENbpXzwDAP7eFeR10923lsK</credentialsNumber><credentialsType>9</credentialsType><address>111</address><issuingAuthority>123</issuingAuthority><expiryDate>1992-08-12</expiryDate><company>123</company><tempAddress>bhhj</tempAddress><contactInformation>66</contactInformation><collectionSite>sss</collectionSite><collectionMode>3</collectionMode><collectionType>0</collectionType><credentialsPhotoType>1</credentialsPhotoType><credentialsPhoto>/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCACgAHgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4 Tl5ufo6erx8vP09fb3 Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3 Pn6/9oADAMBAAIRAxEAPwD3 iiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiua8W NNO8KWLPMwlu2wI7dTySe59BQB0FxcwWkDz3EqRRIMs7tgD8a4fWPixoOnZW0El 47x/Kv5mvH/EXjDVfEUzyX90zQFspAhwifQf1NczJcsx9R7UAemal8Z9aeUmyht7ePPAK7zj3zWHL8UvFE53JqzofRY0A/lXCySEsf51EhO5hnlTQB6JafF/xRbEb7yKcA8rLEDn8Riuw0f45WskiR6xpzQgnBmt23AfVTz teEyEhlPr1pAzDPr0oA ydN1Ww1i0W70 7iuYG6PG2fz9KuV8heHPE p G9QW7065aJv4l6q49GHevorwP8AEPT/ABfD5D7bbU0GXty3De6eo9u1AHZ0UUUAFFFFABRRRQBieJ/Elr4Z0mS9uAGI4VM4yT0r5p8Qa3da1q813dP8zMWCjoAef8/QV1XxO8RvrfiOa0iOLSyOFAP336bj/SuGOJ1zxkcZoAY5Zz1GRUO3JzmpgCvynjHeqs9wUf5eB3FMAdASxH1FMXasu7sQKh84k5zwaaSSOOaQFiUKxBzwKYQPlx NRbj3PPpTk3MODQAKvz4qxBdT2V3Fc28rRTRkMjqcFSKrsWBzj60omBGGAoGfTvw28cL4u0gxXLKup2wAmX/novZx/I /1ruK TfB2vXHhnxFa6lC25I2xKmfvxnhh XP1Ar6vhlSeCOaNt0cihlPqCMikA iiimIKoa3d/YNDvrvODFAzD644q/XPeOS3/CF6mFOGMYUfiwFAHzZcSvcXM08hy8khdj71l2jMjOPcg1a3FVlBPzLJj9KqyuE5HG7k0wNHT9OudYfyrZNzn1OM/jUN/4b1e1cifTpwR3CEj9K6v4aGFo7qRyA3mgDuenavSru4lmh2Q74gB97yiSaxlNpm8aaaPnyDRNRmYhbGfj/AGDUh0q6ixutZgenKmvZDdvGxD3cjY6 ZEB/StZBHLbrKFVgR1AzWft2tkX9XXU8NGj37x7o7CRyemRgCq1xYalbRGSSzITvgZx VeuXqWUpdriWRY1ODsJA/OqsCaLJCRbs HJUEOMMfTk80vbN62H7CO1zx3zxnBXg9RSPGFbqQD0rq/EPh4JLK0KMPlLA7eP0rllBmtkI 8Tt/Kt4S5lc55x5XYdbS U4yePavqH4Y6/FrHgqxV5V 0Ww zupPJ29P0xXy15LBgD Ne//AAR0KOHR7jVZCzSPJ5cat0QYGSPc5qiT1qiiimIKyvEtq154fu4V6lcj8Dn latNkQSRsh6MMUAfJ2rxJHqt9FGwI81tv4GsK7YrECPcV3XjjSZNI8W3iSRhVLblIGAytyD/AJ9K5C6tdyMvH3u1AzrfhxcTPbylGSGIlUORjLDOeffINejyaJHdjzZppZOCAm/5Rn271wHwhnVftts3Zw2PUYr1G7srORSfIUE914/lXPN 8zrpr3UcM2hRaZMywTyl3fd8zZJ9vpV630mf yZDdtmSVyVPIx74rdtrC1glyIgHNaFxAht8EgN6GsXdpm0Uk0cLawFyI79xvjLIobgbSMY9DxWpbaNpkNp5MUcSx53Y3d/WtCW3WLO5Qyn IcipoLaEKGWKP8FFRzNqzK5V0OT1XShtkCO75Qqoj5xn1PQCvL54/st5NG N8bEEjvX0RIUNuQQOPWvAPFrAeKb4LgDeDx9BW1CWvKc9eOnMUo0V5jKTx2HvX0N8G7kS FZYf ecx4 tfOyyjyWA7HtXsHwYvJrWaZPMzBOQCh9cHkV1HIe4UUUUxBQTjrRSMiupVgCp6g0AeafFzSLO90uO NxHHcwjbtLAbkznPqSPT3NeHSODhRzkj9K j/FOg6O1qZZNPjeXBCszHAPbjPJ9q8D8TaXHpWtrbxuGyPMYAYCk9h9OOaADwFcmz8VMgOElBGK9tUllB7V886DqJtPFVoW2iOSYKTjpngV9A27jyVye1ctVe9c7KL92wvlZk35xjpWYmkw6fJPPFPKZ7qQM5kkLL AJwPwq1e35tIWZYjK3ZV6msK5uNUnBkYRgHoocDbWe60OiEW2Tw6bDYtOttuWOeQySDcWy5789K1LdiEwa5tZ9TtiCqxyjugbOa37WcvGpddrdxWL0epq4taE8zYiYDuK8K8Xsn/CQXGJFZixyo6j617jM4KMf4cV873jC 1m8uB0lnZgfbNbYdXk2cuJdo2G2ymV/lBOeuK9z Hnh26tbFNisC DjP3cHqK5X4ceDG1No3khPlvMpMjDgIpyce RX0LZadbafHst49oxjPeu1HCTxKyRKrOXIGCx70U imIKKKKAMvV7a5uICIsYH3Qi/OfoTwK8a8e D7y1tW1OWBLdCSCA292J9T/kV7zXOeO9MbVfB oQR58xYzIuO OcUAfJdxFhxtJDA8EV7R4O8SpruiIznF3BiOdfU9mH1Fec FNC/4SHUblGOEiiLgDqx9BXpOleCD4ahW7SbdFqC7gmMFCPT2IIrKtH3Lm1CVp2NtkaQfLz9apzaY0gy7hB6inJcy2rYkQsnqKSfVIG4LY tcWh6CvfQbHYtGoVH3AVMAYx8xqCK/jPCEn6UkjSzNz8i/rWTsXr1Mbxzrz6T4Zn z/6 ciBWH8AbqfrjNePWp2rwO2a9H JQA0CBQP8Al4X RrlPCOhTa54is9PiQsJGy3GcADJzXdhl7h5 Jfvn0l8N7aK38C6YYwMvHuPGCD7 9dZVHR7D zNKt7Pdu8pAucYq9XScwUUUUAFFFNd1RSzsFUdSTigB1MmjWaGSJvuupU/QiuZ1XxdDEZIbHEjqDmTt HrXJXGuXWoiwEtzIyCTLZbGWwcZ/GrcGouTO6GArSg5tWRyZ0C9 G2uyXUbwXkbll ykkNIp6YIziutt/EOo IwHvbGKygiAEMKMWIz1JP5cCnvAsshd13H1PWpFQRj5RiuKdRyViIUlF3G7Qcg1SuYEb AH61cLgHNRyMpHNYPY6EylBGqHhAKmfmmqyhulOLAmsTQw/E2jjV9N zbiDncD6EVv/CrTNE0fzZHudupOSm2YbTt9j0NMkTeORWdPa/NkDHNbU6zhoZVKKnqe2jpRXlGk INT0ohUnMkI/5ZyHI/D0rpbfx/bG78i6tJI8ruDo24e/FdlOtGenU5nhal7RVzsqKp2Gp2epReZaTrIB1A6j8KK1OeUXF2aszG1/xONPDR2oR5F4ZjyBXCahrt5fk bO7L6E/0qPVZjIJlJOd9ZqEmInv0rqSUdEfW4bA0qMU7XfclWV1lDE5xx9RUeDHJPCvZvMj/AM/Wmk/KPyqabjy5u44Y xob5kdrgrWOgs5xcwJKP4hyKmOAKzdIP7uSMfwtkD2NaIyOa8iUeVtM Zq03Cbj2K0q56VUdyGINajgFTVN4gx5rKSFEqF8dKkjBJzUy24J9aXbtOAKjlKuA6D3proGGcU4hs5NIRJjgfjVWAgZVUc1kXMm24eX0XArXljKxs8hwo/WsST95KB2zk104eGtzvwFLmnzdizp pXOntFLBIySKc7gaKrSfd nFFdtj0p4alN3nFMvXjF7iZT/AHjiqsRwwU9DwakuZCl9KrdN5qFm2zA/jWretzeOwsg2sR71YGJICpqGb5kDjvUls24MKI7tDa6j7G6a2mDHnHDe4rofODoCvIIzXMSKVfcO3X3q9Y3uxQjnK9jXJXpt 8jzMfhnP95DfqaZdunakHJp67ZFyDTSCK4WjyEx6YUUpbceAKYvSpEQUIT01FGPTNDfTFSIgzWfqV sIMaEF/5VtCDloiqUJVZcsSjqd1uPlg8L1qhGpALH7x6 1ABkbzGzgcjPc tOTlTXdCHKrH0lCkqUFFEZGRRT8cEUVaNGf//Z</credentialsPhoto><photograph>/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCACgAHgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4 Tl5ufo6erx8vP09fb3 Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3 Pn6/9oADAMBAAIRAxEAPwDNooor7k ECiiigAoopkkscMZklkWNB/E5wKNhpXH0VlyeI9Hjbab In/ZyR gqRNc0qRwi6hblj0BfH86y9tTenMvvNHQqrXlf3M0KKRSGXcpDD1ByKWtTIKKKKACiiigAooooAKKKKACiiuJ8U ITM7afZyYiXiaRf4j6D2rDEYiNCHNI6MNh54ifJEuaz4wS2drfTlWWQcNM3KqfYd/5Vx15fXN9MZLqZ5X/wBo8D6DoKgxnp VBUD3PrXzVfF1Kz956dj6fD4SlQXurXv1EJz1oJzTTRmue502LVpfXVk  2nkiP8Ast1/Cuu0jxkkpWHUlEbHgTqPl/Edvwrh80ua3oYqrRd4vTt0OavhKVdWmte/U9jVldQysGVhkEHIIpa8 8M6 2nzraXDk2khwM/8sz6j29a9Br6TC4mOIhzLfqfNYrCyw8 V7dGFFFFdJyhRRRQAUUUUAYnifVDp2mFIziefKKR2Hc150qk/U810Hiu5 1a28fVLdQg vU1kRxjYzEYOa YzCs6tZrotD6nL6KpUF3epDtG046Dqe5NNZT1P/wCqrWwZAFMePJxXAd5SI5xRjirXkEjOKUQHpjqKBlUDNLt61aS33Gl zkrn04NAimK9A8I6sbyzNnK2ZYB8pJ5ZP/rVw5ixJj1q7oly n6xBIDhd21voeDXVgq7o1U j3OTG0FWotdVsen0UUV9YfJBRRRQAUZA5PQcmimTZ8iXHXY38qTdkNK7seZXUoluZZevmOWP4kmoMksAO3ajnI74q3ZWM19dxwQKWd vtk18ZKXVn20Y7JDYoGkdEUcmtBNCvp3HlReY2MkLz3r1fRfDXhvSNPjbVRA88cW6QyHO0dzj0rbtE8P3TFtLa1kMeCfJxlf8K5ZVuqOyOHWzZ4xN4P16CGOQ6bNtYZ 77VWbw1rUa720y52hN2fLNfSFr88YBO4U27L7CNxx7Go9u0rl/V4nzU9jdQuqvbOjMcHcuKhvbO606ULLGVVh8rdjXvGoXfhzR5Fk1Uwq75K703E460 6/wCEf1WAQeTCVljDrG8e0lT0IBFHt3vYn6unpfU ek2vKGf1LfpTVwzAj Gun8b FzoN1HPagmyuCQmf4G9K5YfumXJ 9XRCSkro5pwcXZnpumTG40y2lb7zRjP1HFWqztCGNDtD6pn8ya0a 1otunFvsj4mskqkku7CiiitDIKQgMCp6EYpaKAPLZojBPJG3BRip/A16R8MtGkPnanIq XIvlx5HOc81x/iey yam8q/cnHmD2Pcf59a9Y HoUeE7DbjG1s/Xca JxlN05OD7n3WAmqqU12Ojh0S1IfdEG3jD5/iHpUNvoljpZ/0K0jt4w27bENoJ9/Wt6HlAAKSaIJEzyEBVGc159tLHq6lKxkZOW9aszMJMEc81QtWa4YsqkL2zSzySWsgYqSvfFQ3oFrjLjR7K8lLXVrFOu7diVd2D7Z6VLNpNsUGIlwOnFaUQWWJZIyCrDOae4GzkU7XQ1c4XxxpyXfhO7iZfmhXzUPoV/ tmvA5G QeqnH619JeJii6LeF8bRC fyNfPmmWYvtcggwdpk3t/ujk11YOLm RdTgxslBc76HoOnQm30y1hIwUiUEe Ks0UV97FcqSR8BKXM231CiiimSFFFFAGL4l043uneagzJBlseq9/8AGt74YagZNGmsyfmt5cj/AHWGf5g0QwSTyqkaFifbiq/h6xm8N NHtZlCwX0Z8sjpuHzAflmvnM5hT5uaL16o nyOpUS5ZLToz1q0cbVpdTHnWxjU89arWsg8setVL/UFgkCyuEU9zXzsmfTp3HRz30VyCnk SF/1ZXBB/wB7PP5U2Wa uJo5dyiLBBhCg7vqT0/Cqf8Aa1tglZCR3bBx dMGsWyBR5pI/E1lJs2VOW9jotNHk2yxkjdyT NSXDjFYllqiS3CrE28H2Nak7EjFNPQjVPU4r4g35tvDF1g4MmIx Jrz3wppoigk1CQfvJiRH7J/wDXNdP8SmlvG07S7dS0s0pfaPbgfqabb6bc2lnFCbdh5SBTtGRkDmvcyONP2jlN7bHzufTnyKEFvuJRRRX1p8gFFFFAEtvbyXU4hiGXP6V02meFQzK1ywY91/hrotO0a2sIQsUa57t3NayQgAYGK XxmazqNxp6L8T6nB5TCmlKpq/wMZ9Ijt4wI0XAOAAOg74rNvLGGZn86IExlXRj1Vh0xXWbBkfLxWdfwF4pCEwScLXk899z1uS2xn28u6JW5ANPmjWZSGAOaS8tjbW9iAMZypIHcjP NRCQxjDjj1rmqLWx105O1yOO1a3VvLiBVutO yNOoVotoHtV6G4iZRkgj61K1xHtOCAKh3sdCqPuV7eBLdMBRxTpZS3AGWPAAqtNc7n2x/MT6dqjiLrqFopb5pJNoHvg/wCFQnrYiV7XKsWlQz3r6hNErzEBEY87V9BWnBp5JZWBXPQ9RWjDbCK5nhPHzZA9jV5IkRcfrXXDRHFJczuznbjw/b3SbZYVI6BhwfzrktX8P3OlkyAGS37MOo v NenFCAxXHXimTwrPEUdc5HQjrXoYXH1cO9Hddjz8Vl9KutVZ9zx2iuj1/w6bMPd2o/cD70YH3ff6UV9Vh8TCvDngfK4jDToT5Jo9FWNQMmnjPYUPnHFPTlcY4r4NvU 9SHooKnK/jUcqLsIAGakCtjuB7VDMdsbHPNFxlfWLIz6bKkKgyRqJEx6jkfn0/GsWDy7m3SVeVcZFdXuEgjcf3ABjoTXHuP7L1mWyYFYJj50BPTn7y/gf50VVsyqT3RJ9hibkoDSGxiXogq7HhuRTmUZ56Vk0bJlWK3VATiqUkfn IdJiVsbZzKceiqa05GwuBWfoQ 1 L5JRyLaEhfcnj/GpjH3kEnozbnBbWWKnjyxke TVxFOOtRlNt5K2RkngE56cVZUHGe/vXS9DlQioFPOKcyKenFJgkYNHPQGlcdipLbK6MrJlTRV3ZxzRVxm0tDOVNN6jH 7UluQVPrTJF4xSR5U8Vh1NywRxjp NQOvJyBU2R1JppwT1 tUhMjh2gmL FfnA9PpVHX9KOoWwCf8fEZ3wv0w3p9DV2X91NG6Y5ODVtlDRAAn8a0teNmZp8sro4ywuTKm1wVkXhlPrWgdxHFVtZtmsb9bpMFJeWI/vd/z61JFdpJHncMiubZ8rOxNNXRBev5Nu5JwxHFXPCOn/ZLGa9lDCSc/KcchfWq1vaf2re/PnyE5wf4v/rV0d6/kQx2seAWI6dh15ranG2phVn0RGq7mD8jJ/CpRzgHtUStgU NgWzjinJkRJlUYGRQ4AYEU/coFRlhWdy7CsSUPqKKiMuDgjiirTIZMVDDNNEfOe1IJMY5prTAEYNPkDnHlcU3gGlaVQMk81WnuUQct9cdaFBic0ST4wp7gg1bikUqVXkkdhnispZi6oxYOeuRwCKlllkhTZGSs2dzEHIUY6VolYhsdqPlzabdfa4isac5POFH8XH4mubt/DggmWU6lIyZyFdAUcfUV0MUbyWpillZ8nc2TnJqOS0VUYAt5RXO3sp/pVezW7Eqsloi1YzRSRnyx5cqfKVxgj3qFnZ7ou4BzggkdB6VHBavblZ1OZeA249R6U2SZBctIgIVuCp5207diVLuXVTccDvUvklelR2reYM4OKtEjGefrXPNHRFkBGTzSheakIB/GkVQMtiosVcimT5feipGxtINFWiGf/9k=</photograph><operator>15700085065</operator><submissionType>0</submissionType><personnelID>1</personnelID><credentialsPhotoID>1</credentialsPhotoID><photographID>1</photographID><personnelType>1</personnelType><community>330327001002</community><brithday>1980-01-01</brithday></body>";//OK
                //infoStr = "<body><name>JYKnZKNMbourZR99xI4EBFaFUGHiIaahJtYMVcfvyBEayAzySgmSTA /rTHzp3ybV377z69083Kv99/lfpripA vNn/L9CH0uHT5GUUAQzf4cJINHYBgW1SdQfRtg7QmFiyNvEYvFW6i7ByCsOyOE/imyaWmHitzVPgt6uXWZKVmANQu7CtAicfqvNgwY464g91jhZ44dn5GhaEMl3BOqTlc</name><sex>1</sex><nation>han</nation><credentialsNumber>AUAdr2Ktm8CBOiwodAnr7SAO9SwL/I/Y9NEru0CODba4d96tT6j/O0RKXfeqvaODi4WnZMBNle mr1aLiSb5WwEmWcogJTANFLFi YVvKUHJt g/cDye5tQEo9eQmpB7DviCH/iu3M uYaJCTdlyumzyB7FjN evEO3x8HwkWALws5oycSE8K1SVfsDMQJE0pENbpXzwDAP7eFeR10923lsK</credentialsNumber><credentialsType>9</credentialsType><address>111</address><issuingAuthority>123</issuingAuthority><expiryDate>1992-08-12</expiryDate><company>123</company><tempAddress>bhhj</tempAddress><contactInformation>66</contactInformation><collectionSite>sss</collectionSite><collectionMode>3</collectionMode><collectionType>0</collectionType><credentialsPhotoType>1</credentialsPhotoType><credentialsPhoto>/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCACgAHgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4 Tl5ufo6erx8vP09fb3 Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3 Pn6/9oADAMBAAIRAxEAPwD3 iiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiua8W NNO8KWLPMwlu2wI7dTySe59BQB0FxcwWkDz3EqRRIMs7tgD8a4fWPixoOnZW0El 47x/Kv5mvH/EXjDVfEUzyX90zQFspAhwifQf1NczJcsx9R7UAemal8Z9aeUmyht7ePPAK7zj3zWHL8UvFE53JqzofRY0A/lXCySEsf51EhO5hnlTQB6JafF/xRbEb7yKcA8rLEDn8Riuw0f45WskiR6xpzQgnBmt23AfVTz teEyEhlPr1pAzDPr0oA ydN1Ww1i0W70 7iuYG6PG2fz9KuV8heHPE p G9QW7065aJv4l6q49GHevorwP8AEPT/ABfD5D7bbU0GXty3De6eo9u1AHZ0UUUAFFFFABRRRQBieJ/Elr4Z0mS9uAGI4VM4yT0r5p8Qa3da1q813dP8zMWCjoAef8/QV1XxO8RvrfiOa0iOLSyOFAP336bj/SuGOJ1zxkcZoAY5Zz1GRUO3JzmpgCvynjHeqs9wUf5eB3FMAdASxH1FMXasu7sQKh84k5zwaaSSOOaQFiUKxBzwKYQPlx NRbj3PPpTk3MODQAKvz4qxBdT2V3Fc28rRTRkMjqcFSKrsWBzj60omBGGAoGfTvw28cL4u0gxXLKup2wAmX/novZx/I /1ruK TfB2vXHhnxFa6lC25I2xKmfvxnhh XP1Ar6vhlSeCOaNt0cihlPqCMikA iiimIKoa3d/YNDvrvODFAzD644q/XPeOS3/CF6mFOGMYUfiwFAHzZcSvcXM08hy8khdj71l2jMjOPcg1a3FVlBPzLJj9KqyuE5HG7k0wNHT9OudYfyrZNzn1OM/jUN/4b1e1cifTpwR3CEj9K6v4aGFo7qRyA3mgDuenavSru4lmh2Q74gB97yiSaxlNpm8aaaPnyDRNRmYhbGfj/AGDUh0q6ixutZgenKmvZDdvGxD3cjY6 ZEB/StZBHLbrKFVgR1AzWft2tkX9XXU8NGj37x7o7CRyemRgCq1xYalbRGSSzITvgZx VeuXqWUpdriWRY1ODsJA/OqsCaLJCRbs HJUEOMMfTk80vbN62H7CO1zx3zxnBXg9RSPGFbqQD0rq/EPh4JLK0KMPlLA7eP0rllBmtkI 8Tt/Kt4S5lc55x5XYdbS U4yePavqH4Y6/FrHgqxV5V 0Ww zupPJ29P0xXy15LBgD Ne//AAR0KOHR7jVZCzSPJ5cat0QYGSPc5qiT1qiiimIKyvEtq154fu4V6lcj8Dn latNkQSRsh6MMUAfJ2rxJHqt9FGwI81tv4GsK7YrECPcV3XjjSZNI8W3iSRhVLblIGAytyD/AJ9K5C6tdyMvH3u1AzrfhxcTPbylGSGIlUORjLDOeffINejyaJHdjzZppZOCAm/5Rn271wHwhnVftts3Zw2PUYr1G7srORSfIUE914/lXPN 8zrpr3UcM2hRaZMywTyl3fd8zZJ9vpV630mf yZDdtmSVyVPIx74rdtrC1glyIgHNaFxAht8EgN6GsXdpm0Uk0cLawFyI79xvjLIobgbSMY9DxWpbaNpkNp5MUcSx53Y3d/WtCW3WLO5Qyn IcipoLaEKGWKP8FFRzNqzK5V0OT1XShtkCO75Qqoj5xn1PQCvL54/st5NG N8bEEjvX0RIUNuQQOPWvAPFrAeKb4LgDeDx9BW1CWvKc9eOnMUo0V5jKTx2HvX0N8G7kS FZYf ecx4 tfOyyjyWA7HtXsHwYvJrWaZPMzBOQCh9cHkV1HIe4UUUUxBQTjrRSMiupVgCp6g0AeafFzSLO90uO NxHHcwjbtLAbkznPqSPT3NeHSODhRzkj9K j/FOg6O1qZZNPjeXBCszHAPbjPJ9q8D8TaXHpWtrbxuGyPMYAYCk9h9OOaADwFcmz8VMgOElBGK9tUllB7V886DqJtPFVoW2iOSYKTjpngV9A27jyVye1ctVe9c7KL92wvlZk35xjpWYmkw6fJPPFPKZ7qQM5kkLL AJwPwq1e35tIWZYjK3ZV6msK5uNUnBkYRgHoocDbWe60OiEW2Tw6bDYtOttuWOeQySDcWy5789K1LdiEwa5tZ9TtiCqxyjugbOa37WcvGpddrdxWL0epq4taE8zYiYDuK8K8Xsn/CQXGJFZixyo6j617jM4KMf4cV873jC 1m8uB0lnZgfbNbYdXk2cuJdo2G2ymV/lBOeuK9z Hnh26tbFNisC DjP3cHqK5X4ceDG1No3khPlvMpMjDgIpyce RX0LZadbafHst49oxjPeu1HCTxKyRKrOXIGCx70U imIKKKKAMvV7a5uICIsYH3Qi/OfoTwK8a8e D7y1tW1OWBLdCSCA292J9T/kV7zXOeO9MbVfB oQR58xYzIuO OcUAfJdxFhxtJDA8EV7R4O8SpruiIznF3BiOdfU9mH1Fec FNC/4SHUblGOEiiLgDqx9BXpOleCD4ahW7SbdFqC7gmMFCPT2IIrKtH3Lm1CVp2NtkaQfLz9apzaY0gy7hB6inJcy2rYkQsnqKSfVIG4LY tcWh6CvfQbHYtGoVH3AVMAYx8xqCK/jPCEn6UkjSzNz8i/rWTsXr1Mbxzrz6T4Zn z/6 ciBWH8AbqfrjNePWp2rwO2a9H JQA0CBQP8Al4X RrlPCOhTa54is9PiQsJGy3GcADJzXdhl7h5 Jfvn0l8N7aK38C6YYwMvHuPGCD7 9dZVHR7D zNKt7Pdu8pAucYq9XScwUUUUAFFFNd1RSzsFUdSTigB1MmjWaGSJvuupU/QiuZ1XxdDEZIbHEjqDmTt HrXJXGuXWoiwEtzIyCTLZbGWwcZ/GrcGouTO6GArSg5tWRyZ0C9 G2uyXUbwXkbll ykkNIp6YIziutt/EOo IwHvbGKygiAEMKMWIz1JP5cCnvAsshd13H1PWpFQRj5RiuKdRyViIUlF3G7Qcg1SuYEb AH61cLgHNRyMpHNYPY6EylBGqHhAKmfmmqyhulOLAmsTQw/E2jjV9N zbiDncD6EVv/CrTNE0fzZHudupOSm2YbTt9j0NMkTeORWdPa/NkDHNbU6zhoZVKKnqe2jpRXlGk INT0ohUnMkI/5ZyHI/D0rpbfx/bG78i6tJI8ruDo24e/FdlOtGenU5nhal7RVzsqKp2Gp2epReZaTrIB1A6j8KK1OeUXF2aszG1/xONPDR2oR5F4ZjyBXCahrt5fk bO7L6E/0qPVZjIJlJOd9ZqEmInv0rqSUdEfW4bA0qMU7XfclWV1lDE5xx9RUeDHJPCvZvMj/AM/Wmk/KPyqabjy5u44Y xob5kdrgrWOgs5xcwJKP4hyKmOAKzdIP7uSMfwtkD2NaIyOa8iUeVtM Zq03Cbj2K0q56VUdyGINajgFTVN4gx5rKSFEqF8dKkjBJzUy24J9aXbtOAKjlKuA6D3proGGcU4hs5NIRJjgfjVWAgZVUc1kXMm24eX0XArXljKxs8hwo/WsST95KB2zk104eGtzvwFLmnzdizp pXOntFLBIySKc7gaKrSfd nFFdtj0p4alN3nFMvXjF7iZT/AHjiqsRwwU9DwakuZCl9KrdN5qFm2zA/jWretzeOwsg2sR71YGJICpqGb5kDjvUls24MKI7tDa6j7G6a2mDHnHDe4rofODoCvIIzXMSKVfcO3X3q9Y3uxQjnK9jXJXpt 8jzMfhnP95DfqaZdunakHJp67ZFyDTSCK4WjyEx6YUUpbceAKYvSpEQUIT01FGPTNDfTFSIgzWfqV sIMaEF/5VtCDloiqUJVZcsSjqd1uPlg8L1qhGpALH7x6 1ABkbzGzgcjPc tOTlTXdCHKrH0lCkqUFFEZGRRT8cEUVaNGf//Z</credentialsPhoto><photograph>/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCACgAHgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4 Tl5ufo6erx8vP09fb3 Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3 Pn6/9oADAMBAAIRAxEAPwDNooor7k ECiiigAoopkkscMZklkWNB/E5wKNhpXH0VlyeI9Hjbab In/ZyR gqRNc0qRwi6hblj0BfH86y9tTenMvvNHQqrXlf3M0KKRSGXcpDD1ByKWtTIKKKKACiiigAooooAKKKKACiiuJ8U ITM7afZyYiXiaRf4j6D2rDEYiNCHNI6MNh54ifJEuaz4wS2drfTlWWQcNM3KqfYd/5Vx15fXN9MZLqZ5X/wBo8D6DoKgxnp VBUD3PrXzVfF1Kz956dj6fD4SlQXurXv1EJz1oJzTTRmue502LVpfXVk  2nkiP8Ast1/Cuu0jxkkpWHUlEbHgTqPl/Edvwrh80ua3oYqrRd4vTt0OavhKVdWmte/U9jVldQysGVhkEHIIpa8 8M6 2nzraXDk2khwM/8sz6j29a9Br6TC4mOIhzLfqfNYrCyw8 V7dGFFFFdJyhRRRQAUUUUAYnifVDp2mFIziefKKR2Hc150qk/U810Hiu5 1a28fVLdQg vU1kRxjYzEYOa YzCs6tZrotD6nL6KpUF3epDtG046Dqe5NNZT1P/wCqrWwZAFMePJxXAd5SI5xRjirXkEjOKUQHpjqKBlUDNLt61aS33Gl zkrn04NAimK9A8I6sbyzNnK2ZYB8pJ5ZP/rVw5ixJj1q7oly n6xBIDhd21voeDXVgq7o1U j3OTG0FWotdVsen0UUV9YfJBRRRQAUZA5PQcmimTZ8iXHXY38qTdkNK7seZXUoluZZevmOWP4kmoMksAO3ajnI74q3ZWM19dxwQKWd vtk18ZKXVn20Y7JDYoGkdEUcmtBNCvp3HlReY2MkLz3r1fRfDXhvSNPjbVRA88cW6QyHO0dzj0rbtE8P3TFtLa1kMeCfJxlf8K5ZVuqOyOHWzZ4xN4P16CGOQ6bNtYZ 77VWbw1rUa720y52hN2fLNfSFr88YBO4U27L7CNxx7Go9u0rl/V4nzU9jdQuqvbOjMcHcuKhvbO606ULLGVVh8rdjXvGoXfhzR5Fk1Uwq75K703E460 6/wCEf1WAQeTCVljDrG8e0lT0IBFHt3vYn6unpfU ek2vKGf1LfpTVwzAj Gun8b FzoN1HPagmyuCQmf4G9K5YfumXJ 9XRCSkro5pwcXZnpumTG40y2lb7zRjP1HFWqztCGNDtD6pn8ya0a 1otunFvsj4mskqkku7CiiitDIKQgMCp6EYpaKAPLZojBPJG3BRip/A16R8MtGkPnanIq XIvlx5HOc81x/iey yam8q/cnHmD2Pcf59a9Y HoUeE7DbjG1s/Xca JxlN05OD7n3WAmqqU12Ojh0S1IfdEG3jD5/iHpUNvoljpZ/0K0jt4w27bENoJ9/Wt6HlAAKSaIJEzyEBVGc159tLHq6lKxkZOW9aszMJMEc81QtWa4YsqkL2zSzySWsgYqSvfFQ3oFrjLjR7K8lLXVrFOu7diVd2D7Z6VLNpNsUGIlwOnFaUQWWJZIyCrDOae4GzkU7XQ1c4XxxpyXfhO7iZfmhXzUPoV/ tmvA5G QeqnH619JeJii6LeF8bRC fyNfPmmWYvtcggwdpk3t/ujk11YOLm RdTgxslBc76HoOnQm30y1hIwUiUEe Ks0UV97FcqSR8BKXM231CiiimSFFFFAGL4l043uneagzJBlseq9/8AGt74YagZNGmsyfmt5cj/AHWGf5g0QwSTyqkaFifbiq/h6xm8N NHtZlCwX0Z8sjpuHzAflmvnM5hT5uaL16o nyOpUS5ZLToz1q0cbVpdTHnWxjU89arWsg8setVL/UFgkCyuEU9zXzsmfTp3HRz30VyCnk SF/1ZXBB/wB7PP5U2Wa uJo5dyiLBBhCg7vqT0/Cqf8Aa1tglZCR3bBx dMGsWyBR5pI/E1lJs2VOW9jotNHk2yxkjdyT NSXDjFYllqiS3CrE28H2Nak7EjFNPQjVPU4r4g35tvDF1g4MmIx Jrz3wppoigk1CQfvJiRH7J/wDXNdP8SmlvG07S7dS0s0pfaPbgfqabb6bc2lnFCbdh5SBTtGRkDmvcyONP2jlN7bHzufTnyKEFvuJRRRX1p8gFFFFAEtvbyXU4hiGXP6V02meFQzK1ywY91/hrotO0a2sIQsUa57t3NayQgAYGK XxmazqNxp6L8T6nB5TCmlKpq/wMZ9Ijt4wI0XAOAAOg74rNvLGGZn86IExlXRj1Vh0xXWbBkfLxWdfwF4pCEwScLXk899z1uS2xn28u6JW5ANPmjWZSGAOaS8tjbW9iAMZypIHcjP NRCQxjDjj1rmqLWx105O1yOO1a3VvLiBVutO yNOoVotoHtV6G4iZRkgj61K1xHtOCAKh3sdCqPuV7eBLdMBRxTpZS3AGWPAAqtNc7n2x/MT6dqjiLrqFopb5pJNoHvg/wCFQnrYiV7XKsWlQz3r6hNErzEBEY87V9BWnBp5JZWBXPQ9RWjDbCK5nhPHzZA9jV5IkRcfrXXDRHFJczuznbjw/b3SbZYVI6BhwfzrktX8P3OlkyAGS37MOo v NenFCAxXHXimTwrPEUdc5HQjrXoYXH1cO9Hddjz8Vl9KutVZ9zx2iuj1/w6bMPd2o/cD70YH3ff6UV9Vh8TCvDngfK4jDToT5Jo9FWNQMmnjPYUPnHFPTlcY4r4NvU 9SHooKnK/jUcqLsIAGakCtjuB7VDMdsbHPNFxlfWLIz6bKkKgyRqJEx6jkfn0/GsWDy7m3SVeVcZFdXuEgjcf3ABjoTXHuP7L1mWyYFYJj50BPTn7y/gf50VVsyqT3RJ9hibkoDSGxiXogq7HhuRTmUZ56Vk0bJlWK3VATiqUkfn IdJiVsbZzKceiqa05GwuBWfoQ 1 L5JRyLaEhfcnj/GpjH3kEnozbnBbWWKnjyxke TVxFOOtRlNt5K2RkngE56cVZUHGe/vXS9DlQioFPOKcyKenFJgkYNHPQGlcdipLbK6MrJlTRV3ZxzRVxm0tDOVNN6jH 7UluQVPrTJF4xSR5U8Vh1NywRxjp NQOvJyBU2R1JppwT1 tUhMjh2gmL FfnA9PpVHX9KOoWwCf8fEZ3wv0w3p9DV2X91NG6Y5ODVtlDRAAn8a0teNmZp8sro4ywuTKm1wVkXhlPrWgdxHFVtZtmsb9bpMFJeWI/vd/z61JFdpJHncMiubZ8rOxNNXRBev5Nu5JwxHFXPCOn/ZLGa9lDCSc/KcchfWq1vaf2re/PnyE5wf4v/rV0d6/kQx2seAWI6dh15ranG2phVn0RGq7mD8jJ/CpRzgHtUStgU NgWzjinJkRJlUYGRQ4AYEU/coFRlhWdy7CsSUPqKKiMuDgjiirTIZMVDDNNEfOe1IJMY5prTAEYNPkDnHlcU3gGlaVQMk81WnuUQct9cdaFBic0ST4wp7gg1bikUqVXkkdhnispZi6oxYOeuRwCKlllkhTZGSs2dzEHIUY6VolYhsdqPlzabdfa4isac5POFH8XH4mubt/DggmWU6lIyZyFdAUcfUV0MUbyWpillZ8nc2TnJqOS0VUYAt5RXO3sp/pVezW7Eqsloi1YzRSRnyx5cqfKVxgj3qFnZ7ou4BzggkdB6VHBavblZ1OZeA249R6U2SZBctIgIVuCp5207diVLuXVTccDvUvklelR2reYM4OKtEjGefrXPNHRFkBGTzSheakIB/GkVQMtiosVcimT5feipGxtINFWiGf/9k=</photograph><operator>15700085065</operator><submissionType>0</submissionType><personnelID>1</personnelID><credentialsPhotoID>1</credentialsPhotoID><photographID>1</photographID><personnelType>1</personnelType><community>330327001002</community><brithday>1980-01-01</brithday></body>";//KO


                string _accessNumber = "accessNumber=" + personInfo.AccessNumber;
                string info = "&info=" + infoStr;
                string _pwd = "&pwd=" + personInfo.Pwd;
                string md5Text = personInfo.AccessNumber + infoStr1 + personInfo.Pwd;
                //MessageBox.Show(md5Text);
                string md5 = _md5(md5Text);
                string resultdata = _accessNumber + "&md5=" + md5 + info;

                string result = "";
                result = HttpPost("http://211.138.112.188:9555/FloatingPopulationExtranet/api/ldrkCollection.html", resultdata);
                //result = HttpPost("https://wxqwer.mynatapp.cc/api/ldrkCollection.html", resultdata);
                return result;// 100 成功,101 参数错误,102 非法接入用户,103 MD5 校验出错,104 解析 xml 出错,110 必填项缺失
            }
            catch (Exception exp)
            {
                return exp.ToString();
            }
        }
        public string UploadInfoToServerNew(string accessNumber, string pwd)
        {
            //UploadInfoToServer3();
            try
            {
                string _accessNumber = "accessNumber=" + accessNumber;
                string infoKey = "<body><name>JYKnZKNMbourZR99xI4EBFaFUGHiIaahJtYMVcfvyBEayAzySgmSTA /rTHzp3ybV377z69083Kv99/lfpripA vNn/L9CH0uHT5GUUAQzf4cJINHYBgW1SdQfRtg7QmFiyNvEYvFW6i7ByCsOyOE/imyaWmHitzVPgt6uXWZKVmANQu7CtAicfqvNgwY464g91jhZ44dn5GhaEMl3BOqTlc</name><sex>1</sex><nation>han</nation><credentialsNumber>AUAdr2Ktm8CBOiwodAnr7SAO9SwL/I/Y9NEru0CODba4d96tT6j/O0RKXfeqvaODi4WnZMBNle mr1aLiSb5WwEmWcogJTANFLFi YVvKUHJt g/cDye5tQEo9eQmpB7DviCH/iu3M uYaJCTdlyumzyB7FjN evEO3x8HwkWALws5oycSE8K1SVfsDMQJE0pENbpXzwDAP7eFeR10923lsK</credentialsNumber><credentialsType>9</credentialsType><address>111</address><issuingAuthority>123</issuingAuthority><expiryDate>1992-08-12</expiryDate><company>123</company><tempAddress>bhhj</tempAddress><contactInformation>66</contactInformation><collectionSite>sss</collectionSite><collectionMode>3</collectionMode><collectionType>1</collectionType><credentialsPhotoType>1</credentialsPhotoType><credentialsPhoto>/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCACgAHgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4 Tl5ufo6erx8vP09fb3 Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3 Pn6/9oADAMBAAIRAxEAPwD3 iiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiua8W NNO8KWLPMwlu2wI7dTySe59BQB0FxcwWkDz3EqRRIMs7tgD8a4fWPixoOnZW0El 47x/Kv5mvH/EXjDVfEUzyX90zQFspAhwifQf1NczJcsx9R7UAemal8Z9aeUmyht7ePPAK7zj3zWHL8UvFE53JqzofRY0A/lXCySEsf51EhO5hnlTQB6JafF/xRbEb7yKcA8rLEDn8Riuw0f45WskiR6xpzQgnBmt23AfVTz teEyEhlPr1pAzDPr0oA ydN1Ww1i0W70 7iuYG6PG2fz9KuV8heHPE p G9QW7065aJv4l6q49GHevorwP8AEPT/ABfD5D7bbU0GXty3De6eo9u1AHZ0UUUAFFFFABRRRQBieJ/Elr4Z0mS9uAGI4VM4yT0r5p8Qa3da1q813dP8zMWCjoAef8/QV1XxO8RvrfiOa0iOLSyOFAP336bj/SuGOJ1zxkcZoAY5Zz1GRUO3JzmpgCvynjHeqs9wUf5eB3FMAdASxH1FMXasu7sQKh84k5zwaaSSOOaQFiUKxBzwKYQPlx NRbj3PPpTk3MODQAKvz4qxBdT2V3Fc28rRTRkMjqcFSKrsWBzj60omBGGAoGfTvw28cL4u0gxXLKup2wAmX/novZx/I /1ruK TfB2vXHhnxFa6lC25I2xKmfvxnhh XP1Ar6vhlSeCOaNt0cihlPqCMikA iiimIKoa3d/YNDvrvODFAzD644q/XPeOS3/CF6mFOGMYUfiwFAHzZcSvcXM08hy8khdj71l2jMjOPcg1a3FVlBPzLJj9KqyuE5HG7k0wNHT9OudYfyrZNzn1OM/jUN/4b1e1cifTpwR3CEj9K6v4aGFo7qRyA3mgDuenavSru4lmh2Q74gB97yiSaxlNpm8aaaPnyDRNRmYhbGfj/AGDUh0q6ixutZgenKmvZDdvGxD3cjY6 ZEB/StZBHLbrKFVgR1AzWft2tkX9XXU8NGj37x7o7CRyemRgCq1xYalbRGSSzITvgZx VeuXqWUpdriWRY1ODsJA/OqsCaLJCRbs HJUEOMMfTk80vbN62H7CO1zx3zxnBXg9RSPGFbqQD0rq/EPh4JLK0KMPlLA7eP0rllBmtkI 8Tt/Kt4S5lc55x5XYdbS U4yePavqH4Y6/FrHgqxV5V 0Ww zupPJ29P0xXy15LBgD Ne//AAR0KOHR7jVZCzSPJ5cat0QYGSPc5qiT1qiiimIKyvEtq154fu4V6lcj8Dn latNkQSRsh6MMUAfJ2rxJHqt9FGwI81tv4GsK7YrECPcV3XjjSZNI8W3iSRhVLblIGAytyD/AJ9K5C6tdyMvH3u1AzrfhxcTPbylGSGIlUORjLDOeffINejyaJHdjzZppZOCAm/5Rn271wHwhnVftts3Zw2PUYr1G7srORSfIUE914/lXPN 8zrpr3UcM2hRaZMywTyl3fd8zZJ9vpV630mf yZDdtmSVyVPIx74rdtrC1glyIgHNaFxAht8EgN6GsXdpm0Uk0cLawFyI79xvjLIobgbSMY9DxWpbaNpkNp5MUcSx53Y3d/WtCW3WLO5Qyn IcipoLaEKGWKP8FFRzNqzK5V0OT1XShtkCO75Qqoj5xn1PQCvL54/st5NG N8bEEjvX0RIUNuQQOPWvAPFrAeKb4LgDeDx9BW1CWvKc9eOnMUo0V5jKTx2HvX0N8G7kS FZYf ecx4 tfOyyjyWA7HtXsHwYvJrWaZPMzBOQCh9cHkV1HIe4UUUUxBQTjrRSMiupVgCp6g0AeafFzSLO90uO NxHHcwjbtLAbkznPqSPT3NeHSODhRzkj9K j/FOg6O1qZZNPjeXBCszHAPbjPJ9q8D8TaXHpWtrbxuGyPMYAYCk9h9OOaADwFcmz8VMgOElBGK9tUllB7V886DqJtPFVoW2iOSYKTjpngV9A27jyVye1ctVe9c7KL92wvlZk35xjpWYmkw6fJPPFPKZ7qQM5kkLL AJwPwq1e35tIWZYjK3ZV6msK5uNUnBkYRgHoocDbWe60OiEW2Tw6bDYtOttuWOeQySDcWy5789K1LdiEwa5tZ9TtiCqxyjugbOa37WcvGpddrdxWL0epq4taE8zYiYDuK8K8Xsn/CQXGJFZixyo6j617jM4KMf4cV873jC 1m8uB0lnZgfbNbYdXk2cuJdo2G2ymV/lBOeuK9z Hnh26tbFNisC DjP3cHqK5X4ceDG1No3khPlvMpMjDgIpyce RX0LZadbafHst49oxjPeu1HCTxKyRKrOXIGCx70U imIKKKKAMvV7a5uICIsYH3Qi/OfoTwK8a8e D7y1tW1OWBLdCSCA292J9T/kV7zXOeO9MbVfB oQR58xYzIuO OcUAfJdxFhxtJDA8EV7R4O8SpruiIznF3BiOdfU9mH1Fec FNC/4SHUblGOEiiLgDqx9BXpOleCD4ahW7SbdFqC7gmMFCPT2IIrKtH3Lm1CVp2NtkaQfLz9apzaY0gy7hB6inJcy2rYkQsnqKSfVIG4LY tcWh6CvfQbHYtGoVH3AVMAYx8xqCK/jPCEn6UkjSzNz8i/rWTsXr1Mbxzrz6T4Zn z/6 ciBWH8AbqfrjNePWp2rwO2a9H JQA0CBQP8Al4X RrlPCOhTa54is9PiQsJGy3GcADJzXdhl7h5 Jfvn0l8N7aK38C6YYwMvHuPGCD7 9dZVHR7D zNKt7Pdu8pAucYq9XScwUUUUAFFFNd1RSzsFUdSTigB1MmjWaGSJvuupU/QiuZ1XxdDEZIbHEjqDmTt HrXJXGuXWoiwEtzIyCTLZbGWwcZ/GrcGouTO6GArSg5tWRyZ0C9 G2uyXUbwXkbll ykkNIp6YIziutt/EOo IwHvbGKygiAEMKMWIz1JP5cCnvAsshd13H1PWpFQRj5RiuKdRyViIUlF3G7Qcg1SuYEb AH61cLgHNRyMpHNYPY6EylBGqHhAKmfmmqyhulOLAmsTQw/E2jjV9N zbiDncD6EVv/CrTNE0fzZHudupOSm2YbTt9j0NMkTeORWdPa/NkDHNbU6zhoZVKKnqe2jpRXlGk INT0ohUnMkI/5ZyHI/D0rpbfx/bG78i6tJI8ruDo24e/FdlOtGenU5nhal7RVzsqKp2Gp2epReZaTrIB1A6j8KK1OeUXF2aszG1/xONPDR2oR5F4ZjyBXCahrt5fk bO7L6E/0qPVZjIJlJOd9ZqEmInv0rqSUdEfW4bA0qMU7XfclWV1lDE5xx9RUeDHJPCvZvMj/AM/Wmk/KPyqabjy5u44Y xob5kdrgrWOgs5xcwJKP4hyKmOAKzdIP7uSMfwtkD2NaIyOa8iUeVtM Zq03Cbj2K0q56VUdyGINajgFTVN4gx5rKSFEqF8dKkjBJzUy24J9aXbtOAKjlKuA6D3proGGcU4hs5NIRJjgfjVWAgZVUc1kXMm24eX0XArXljKxs8hwo/WsST95KB2zk104eGtzvwFLmnzdizp pXOntFLBIySKc7gaKrSfd nFFdtj0p4alN3nFMvXjF7iZT/AHjiqsRwwU9DwakuZCl9KrdN5qFm2zA/jWretzeOwsg2sR71YGJICpqGb5kDjvUls24MKI7tDa6j7G6a2mDHnHDe4rofODoCvIIzXMSKVfcO3X3q9Y3uxQjnK9jXJXpt 8jzMfhnP95DfqaZdunakHJp67ZFyDTSCK4WjyEx6YUUpbceAKYvSpEQUIT01FGPTNDfTFSIgzWfqV sIMaEF/5VtCDloiqUJVZcsSjqd1uPlg8L1qhGpALH7x6 1ABkbzGzgcjPc tOTlTXdCHKrH0lCkqUFFEZGRRT8cEUVaNGf//Z</credentialsPhoto><photograph>/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCACgAHgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4 Tl5ufo6erx8vP09fb3 Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3 Pn6/9oADAMBAAIRAxEAPwDNooor7k ECiiigAoopkkscMZklkWNB/E5wKNhpXH0VlyeI9Hjbab In/ZyR gqRNc0qRwi6hblj0BfH86y9tTenMvvNHQqrXlf3M0KKRSGXcpDD1ByKWtTIKKKKACiiigAooooAKKKKACiiuJ8U ITM7afZyYiXiaRf4j6D2rDEYiNCHNI6MNh54ifJEuaz4wS2drfTlWWQcNM3KqfYd/5Vx15fXN9MZLqZ5X/wBo8D6DoKgxnp VBUD3PrXzVfF1Kz956dj6fD4SlQXurXv1EJz1oJzTTRmue502LVpfXVk  2nkiP8Ast1/Cuu0jxkkpWHUlEbHgTqPl/Edvwrh80ua3oYqrRd4vTt0OavhKVdWmte/U9jVldQysGVhkEHIIpa8 8M6 2nzraXDk2khwM/8sz6j29a9Br6TC4mOIhzLfqfNYrCyw8 V7dGFFFFdJyhRRRQAUUUUAYnifVDp2mFIziefKKR2Hc150qk/U810Hiu5 1a28fVLdQg vU1kRxjYzEYOa YzCs6tZrotD6nL6KpUF3epDtG046Dqe5NNZT1P/wCqrWwZAFMePJxXAd5SI5xRjirXkEjOKUQHpjqKBlUDNLt61aS33Gl zkrn04NAimK9A8I6sbyzNnK2ZYB8pJ5ZP/rVw5ixJj1q7oly n6xBIDhd21voeDXVgq7o1U j3OTG0FWotdVsen0UUV9YfJBRRRQAUZA5PQcmimTZ8iXHXY38qTdkNK7seZXUoluZZevmOWP4kmoMksAO3ajnI74q3ZWM19dxwQKWd vtk18ZKXVn20Y7JDYoGkdEUcmtBNCvp3HlReY2MkLz3r1fRfDXhvSNPjbVRA88cW6QyHO0dzj0rbtE8P3TFtLa1kMeCfJxlf8K5ZVuqOyOHWzZ4xN4P16CGOQ6bNtYZ 77VWbw1rUa720y52hN2fLNfSFr88YBO4U27L7CNxx7Go9u0rl/V4nzU9jdQuqvbOjMcHcuKhvbO606ULLGVVh8rdjXvGoXfhzR5Fk1Uwq75K703E460 6/wCEf1WAQeTCVljDrG8e0lT0IBFHt3vYn6unpfU ek2vKGf1LfpTVwzAj Gun8b FzoN1HPagmyuCQmf4G9K5YfumXJ 9XRCSkro5pwcXZnpumTG40y2lb7zRjP1HFWqztCGNDtD6pn8ya0a 1otunFvsj4mskqkku7CiiitDIKQgMCp6EYpaKAPLZojBPJG3BRip/A16R8MtGkPnanIq XIvlx5HOc81x/iey yam8q/cnHmD2Pcf59a9Y HoUeE7DbjG1s/Xca JxlN05OD7n3WAmqqU12Ojh0S1IfdEG3jD5/iHpUNvoljpZ/0K0jt4w27bENoJ9/Wt6HlAAKSaIJEzyEBVGc159tLHq6lKxkZOW9aszMJMEc81QtWa4YsqkL2zSzySWsgYqSvfFQ3oFrjLjR7K8lLXVrFOu7diVd2D7Z6VLNpNsUGIlwOnFaUQWWJZIyCrDOae4GzkU7XQ1c4XxxpyXfhO7iZfmhXzUPoV/ tmvA5G QeqnH619JeJii6LeF8bRC fyNfPmmWYvtcggwdpk3t/ujk11YOLm RdTgxslBc76HoOnQm30y1hIwUiUEe Ks0UV97FcqSR8BKXM231CiiimSFFFFAGL4l043uneagzJBlseq9/8AGt74YagZNGmsyfmt5cj/AHWGf5g0QwSTyqkaFifbiq/h6xm8N NHtZlCwX0Z8sjpuHzAflmvnM5hT5uaL16o nyOpUS5ZLToz1q0cbVpdTHnWxjU89arWsg8setVL/UFgkCyuEU9zXzsmfTp3HRz30VyCnk SF/1ZXBB/wB7PP5U2Wa uJo5dyiLBBhCg7vqT0/Cqf8Aa1tglZCR3bBx dMGsWyBR5pI/E1lJs2VOW9jotNHk2yxkjdyT NSXDjFYllqiS3CrE28H2Nak7EjFNPQjVPU4r4g35tvDF1g4MmIx Jrz3wppoigk1CQfvJiRH7J/wDXNdP8SmlvG07S7dS0s0pfaPbgfqabb6bc2lnFCbdh5SBTtGRkDmvcyONP2jlN7bHzufTnyKEFvuJRRRX1p8gFFFFAEtvbyXU4hiGXP6V02meFQzK1ywY91/hrotO0a2sIQsUa57t3NayQgAYGK XxmazqNxp6L8T6nB5TCmlKpq/wMZ9Ijt4wI0XAOAAOg74rNvLGGZn86IExlXRj1Vh0xXWbBkfLxWdfwF4pCEwScLXk899z1uS2xn28u6JW5ANPmjWZSGAOaS8tjbW9iAMZypIHcjP NRCQxjDjj1rmqLWx105O1yOO1a3VvLiBVutO yNOoVotoHtV6G4iZRkgj61K1xHtOCAKh3sdCqPuV7eBLdMBRxTpZS3AGWPAAqtNc7n2x/MT6dqjiLrqFopb5pJNoHvg/wCFQnrYiV7XKsWlQz3r6hNErzEBEY87V9BWnBp5JZWBXPQ9RWjDbCK5nhPHzZA9jV5IkRcfrXXDRHFJczuznbjw/b3SbZYVI6BhwfzrktX8P3OlkyAGS37MOo v NenFCAxXHXimTwrPEUdc5HQjrXoYXH1cO9Hddjz8Vl9KutVZ9zx2iuj1/w6bMPd2o/cD70YH3ff6UV9Vh8TCvDngfK4jDToT5Jo9FWNQMmnjPYUPnHFPTlcY4r4NvU 9SHooKnK/jUcqLsIAGakCtjuB7VDMdsbHPNFxlfWLIz6bKkKgyRqJEx6jkfn0/GsWDy7m3SVeVcZFdXuEgjcf3ABjoTXHuP7L1mWyYFYJj50BPTn7y/gf50VVsyqT3RJ9hibkoDSGxiXogq7HhuRTmUZ56Vk0bJlWK3VATiqUkfn IdJiVsbZzKceiqa05GwuBWfoQ 1 L5JRyLaEhfcnj/GpjH3kEnozbnBbWWKnjyxke TVxFOOtRlNt5K2RkngE56cVZUHGe/vXS9DlQioFPOKcyKenFJgkYNHPQGlcdipLbK6MrJlTRV3ZxzRVxm0tDOVNN6jH 7UluQVPrTJF4xSR5U8Vh1NywRxjp NQOvJyBU2R1JppwT1 tUhMjh2gmL FfnA9PpVHX9KOoWwCf8fEZ3wv0w3p9DV2X91NG6Y5ODVtlDRAAn8a0teNmZp8sro4ywuTKm1wVkXhlPrWgdxHFVtZtmsb9bpMFJeWI/vd/z61JFdpJHncMiubZ8rOxNNXRBev5Nu5JwxHFXPCOn/ZLGa9lDCSc/KcchfWq1vaf2re/PnyE5wf4v/rV0d6/kQx2seAWI6dh15ranG2phVn0RGq7mD8jJ/CpRzgHtUStgU NgWzjinJkRJlUYGRQ4AYEU/coFRlhWdy7CsSUPqKKiMuDgjiirTIZMVDDNNEfOe1IJMY5prTAEYNPkDnHlcU3gGlaVQMk81WnuUQct9cdaFBic0ST4wp7gg1bikUqVXkkdhnispZi6oxYOeuRwCKlllkhTZGSs2dzEHIUY6VolYhsdqPlzabdfa4isac5POFH8XH4mubt/DggmWU6lIyZyFdAUcfUV0MUbyWpillZ8nc2TnJqOS0VUYAt5RXO3sp/pVezW7Eqsloi1YzRSRnyx5cqfKVxgj3qFnZ7ou4BzggkdB6VHBavblZ1OZeA249R6U2SZBctIgIVuCp5207diVLuXVTccDvUvklelR2reYM4OKtEjGefrXPNHRFkBGTzSheakIB/GkVQMtiosVcimT5feipGxtINFWiGf/9k=</photograph><operator>15700085065</operator><submissionType>0</submissionType><personnelID>1</personnelID><credentialsPhotoID>1</credentialsPhotoID><photographID>1</photographID><personnelType>1</personnelType><community>330327001002</community><brithday>1980-01-01</brithday></body>";
                //string infoKey = "<body><name>IkqYYugL46ZSpK+k8XtyBgK8FsQ6R2zj2upIOuveJqkYP04jrfNLCPLF88A0AwXPBbYT0NKfOZvKIx+FHQbQtxlFDrPSiM32U9qBVss6O7C+b436AtDhTg8BRGQvW3z7HO9xW2pHdiyNRc8mBSB40ke+TwEVRXmQutA0eeHlXNWfOUNiNz1fM3RcmfNm5mZAJMsp2dyxL19FRN9M7fqjC4aL</name><sex>1</sex><nation>汉族</nation><credentialsNumber>J8EWrD50MqZmtBiSjNDeugctWv/HVqXjzC2mnev2vfDy4uCkcLLuWrqdvVhOvJqJEASbzHOvEF9jsRWIAeqWm8Z62TqlBAOLMAFVJ/sc6WkFflAPwJJBt08342E3BZvHtPivUpZMiha/KjxbSkUhEMlCO24DCjhbVzck73EWVObQewAXrlMBYxaddCc6EEMOkmHsibDlgPxlej1iqFL/3z62</credentialsNumber><credentialsType>1</credentialsType><address>浙江温州</address><issuingAuthority>温州公安</issuingAuthority><expiryDate>2020-09-26</expiryDate><company>_company</company><tempAddress>浙江温州苍南龙港镇123号</tempAddress><contactInformation>13958776325</contactInformation><collectionSite>动车站</collectionSite><collectionMode>3</collectionMode><collectionType>0</collectionType><credentialsPhotoType>1</credentialsPhotoType><credentialsPhoto>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</credentialsPhoto><photograph>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</photograph><operator>林磊</operator><submissionType>0</submissionType><personnelID>1</personnelID><credentialsPhotoID>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</credentialsPhotoID><photographID>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ID</photographID><personnelType>1</personnelType><policestation>sss</policestation><community>330327001002</community><brithday>1980-01-01</brithday></body>";
                // string infoStr = "";
                string info = "&info=" + infoKey;
                string _pwd = "&pwd=" + pwd;
                string md5Text = accessNumber + infoKey + pwd;
                string md5 = _md5(md5Text);
                string resultdata = _accessNumber + "&md5=" + md5 + info;

                string result = "";
                result = HttpPost("http://211.138.112.188:9555/FloatingPopulationExtranet/api/ldrkCollection.html", resultdata);
                //result = HttpPost("https://wxqwer.mynatapp.cc/api/ldrkCollection.html", resultdata);
                return result;// 100 成功,101 参数错误,102 非法接入用户,103 MD5 校验出错,104 解析 xml 出错,110 必填项缺失
            }
            catch (Exception exp)
            {
                return exp.ToString();
            }
        }
        #endregion
        #region 读取TXT文件内容
        /// <summary>
        /// 读取txt文件内容
        /// </summary>
        /// <param name="Path">文件地址</param>
        public void ReadTxtContent(string Path, ref Hashtable ht)
        {
            StreamReader sr = new StreamReader(Path, Encoding.Default);
            string content="",brand="";
            while ((content = sr.ReadLine()) != null)
            {
                content = content.ToString().Trim();
                if(content.Contains("#start")){
                    brand = content.Split(' ')[1];
                }else{
                    if (!ht.ContainsKey(content)) {
                        ht.Add(content, brand);   
                    }
                }
            }
            
        }
        public void ReadTxtContent3(string Path, ref Hashtable ht)
        {
            StreamReader sr = new StreamReader(Path, Encoding.Default);
            string content = "";
            string[] arr;
            while ((content = sr.ReadLine()) != null)
            {
                content = content.ToString().Trim();
                arr = content.Split(' ');
                if (arr.Length > 1) {
                    if (!ht.ContainsKey(arr[0]))
                    {
                        if (arr[1] != null || arr[1].Length > 1)
                        {
                            ht.Add(arr[0], arr[1]);
                        }
                    }   
                }
            }

        }
        public int subStringCount(string str,string a) {
            if (str.Contains('-')) {
                string _str = str.Replace(a, "");
                return str.Length - _str.Length;
            }
            return 0;
        }
        public string strSQL = "";
        public string ReadTxtContent2(string Path, ref Hashtable ht)
        {

            StreamReader sr = new StreamReader(Path, Encoding.Default);
            string content = "",mac="",brand="",strSQL = "";
            while ((content = sr.ReadLine()) != null)
            {
                content = content.ToString().Trim();

                if (content.Length > 18 && subStringCount(content.Substring(0, 8),"-")==2)
                {
                    brand = content.Substring(18).Split(' ')[0];
                    mac = content.Substring(0, 8);
                    //strSQL += "new string[]{'" + brand + "','" + mac + "'},";
                    // strSQL += "new string[]{\"" + brand + "\",\"" + mac + "\"" + "}|";
                    if (!ht.ContainsKey(mac))
                    {
                        ht.Add(mac, brand);
                    }
                    
                }
            }
            Console.WriteLine("strSQL" + strSQL);
            return strSQL;

        }
        #endregion
    }
}
