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


//MD5
using System.Security.Cryptography;
 

namespace WindowsFormsApplication1
{
    public partial class Form1 : Form
    {
        Hashtable ht=new Hashtable(); //创建一个Hashtable实例

        ZJJXJZDll ZJJXJZDll = new ZJJXJZDll();
        
        public Form1()
        {
            InitializeComponent();
            
        }
        private void Form1_Load(object sender, EventArgs e)
        {

            //ZJJXJZDll.ReadTxtContent("mac.txt", ref ht);
            string strSQL = "";
            ZJJXJZDll.ReadTxtContent2("mac_new.txt", ref ht);
            ZJJXJZDll.ReadTxtContent("mac.txt", ref ht);
            ZJJXJZDll.ReadTxtContent3("mac3.txt", ref ht);
            this.Text = ht.Count.ToString();
            //利用循环遍历出key和value
            foreach (DictionaryEntry de in ht) //ht为一个Hashtable实例
            {
                //Console.WriteLine(de.Key);//de.Key对应于key/value键值对key
                //Console.WriteLine(de.Value);//de.Key对应于key/value键值对value
                strSQL += "new string[]{\"" + de.Value + "\",\"" + de.Key + "\"" + "}|";
                //strSQL += de.Key + " " + de.Value + "\r";
            }

            richTextBox1.Text = strSQL;
            //string ss = ZJJXJZDll.ImgBase64(@"3.jpg");
            //string s1 = ZJJXJZDll.ImgBase64(@"4.jpg");

            //  MessageBox.Show(ss.ToString());
            //MessageBox.Show(ss.ToString());
            //string a1 = System.Web.HttpUtility.HtmlDecode("\u6b64\u8bbf\u5ba2\u8bb0\u5f55\u5df2\u7ecf\u767b\u8bb0\u4e0a\u4f20");
            //MessageBox.Show(a1.ToString());
        }
        private void button1_Click(object sender, EventArgs e)
        {
            //设备基本数据上传
            //string url = "http://101.37.162.154/visitortest/web/Rest/visitor/senddeviceno";
            string result = ZJJXJZDll.UpLoadMachineInfToServer("ZJZS001", "浙江赞昇新材料有限公司", "PCS123456", "0573-85261935", "唐伟霞", "127.4545", "127.4564", "wzjydz");
            MessageBox.Show(result.ToString());
        }
        private void button2_Click(object sender, EventArgs e)
        {
            //访客登记数据上传
            /*
             9.31  Json
             9.32  unjson
             */

            //string url = "http://101.37.162.154/visitortest/web/Rest/visitor/sendvisitorinfos";

            string result = ZJJXJZDll.UpLoadVisitorInfToServer("gongyeyuan", "20010", "陈志驾", "男", "330327198209261332", "1982-09-26", "汉", "浙江温州", "13777774772", "3.jpg", "4.jpg",
                "2017-06-09 14:00:00", "2017-06-09 15:00:00", "行政部", "张三", "浙C5SF92", "个人来访");

            MessageBox.Show(result.ToString());
        }


        private void button3_Click(object sender, EventArgs e)
        {
            //访客离开时间上传
            string result = ZJJXJZDll.UpLoadsendleavetimeToServer("ZJZS001", "20008", "2018-04-04 10:01:02");

            MessageBox.Show(result.ToString());
        }

        

        private void button4_Click(object sender, EventArgs e)
        {
            // 信息采集数据上传
            /* string accessNumber, string name, string sex, string nation, string credentialsNumber, string credentialsType, string address,
            string issuingAuthority, string expiryDate, string company, string tempAddress, string contactInformation, string collectionSite, string collectionMode,
            string collectionType, string credentialsPhotoType, string credentialsPhoto, string photograph, string _operator, string submissionType, string personnelID,
            string credentialsPhotoID, string photographID, string personnelType, string community, string brithday, string pwd
             */
            string str = ZJJXJZDll.RSAEncrypt("林祺泰");
            //string result = ZJJXJZDll.UploadInfoToServer("gongyeyuan", "陈志驾", "男", "汉", "330327198209261332", "1", "浙江温州", "温州公安", "2020-09-26", "默默公司", "浙江温州苍南龙港镇123号", "13958776325", "动车站", "1", "0", "1", "3.jpg", "4.jpg", "张三", "0", "121211", "2312321", "2312312", "工人", "12231231", "1999-06-09", "gyy@zjut5607");
            //string result = ZJJXJZDll.UploadInfoToServer4("gongyeyuan", "陈志驾", "男", "汉", "330327198209261332", "1", "浙江温州", "温州公安", "2020-09-26", "默默公司", "浙江温州苍南龙港镇123号", "13958776325", "动车站", "1", "0", "1", "3.jpg", "4.jpg", "张三", "0", "121211", "2312321", "2312312", "工人", "12231231", "1999-06-09", "gyy@zjut5607");
            PersonInfo personInfo = new PersonInfo();
            personInfo.AccessNumber = "gongyeyuan";
            personInfo.Pwd = "gyy@zjut5607";
            personInfo.Name = "林彪";//姓名 必填
            personInfo.Sex = "1";//性别
            personInfo.Nation = "汉族";//民族（文字）
            personInfo.CredentialsNumber = "330327199209261332";//证件号 必填
            personInfo.CredentialsType = "9";//证件类型  证件类型(1居民身份证、2军官证、3武警警官证、4士兵证、5护照、6港澳同胞回乡证、7台湾居民来往大陆通行证、8外国人居留证、9其他)(不能为空) 必填
            personInfo.Address = "111";//户籍地址
            personInfo.IssuingAuthority = "公安";//签发机关
            personInfo.ExpiryDate = "1992-08-12";//有效期
            personInfo.Company = "123";//工作单位
            personInfo.TempAddress = "浙江温州苍南县";//暂住地
            personInfo.ContactInformation = "15700085065";//联系方式（可以是手机或座机）
            personInfo.CollectionSite = "sss";//采集点 必填
            personInfo.CollectionMode = "3";//采集模式(1:公安窗口、2:警务通、3:其他窗口)(不能为空) 必填
            personInfo.CollectionType = "0";//采集类型(0:自动读取、1:人员录入)(不能为空) 必填
            personInfo.CredentialsPhotoType = "1";//证件照片类型(1:身份证人脸照、2:证件照、3:模版照)(不能为空)必填
            personInfo.CredentialsPhoto = "3.jpg";// 证件照 必填
            personInfo.Photograph = "4.jpg";//现场照 必填
            personInfo._operator1 = "15700085065";//操作人员
            personInfo.SubmissionType = "0";//提交类型(0:正常提交、1:强制提交)(不能为空)必填
            personInfo.PersonnelID = " ";//人员信息ID
            personInfo.CredentialsPhotoID = "1";//证件照片ID
            personInfo.PhotographID = " ";//现场照片ID
            personInfo.PersonnelType = " ";//人员类型
            personInfo.Policestation = " ";
            personInfo.Community = "330327001002";//居委会编号（代码） 必填
            personInfo.Brithday = "1980-01-01";// 出生日期

            //string result = ZJJXJZDll.UploadInfoToServerNew("gongyeyuan", "gyy@zjut5607");
            string result = ZJJXJZDll.UploadInfoToHLServer(personInfo);

            MessageBox.Show(result.ToString());
        }

        private void button5_Click(object sender, EventArgs e)
        {
            string mac_text = textBox1.Text.Trim();
            object result = ht[mac_text];
            if (result == null)
            {
                MessageBox.Show("没找到");
                
            }
            else
            {
                MessageBox.Show(ht[mac_text].ToString());
            }
            
            //string str = "";
            //ZJJXJZDll.ReadTxtContent("mac.txt");
        }
    }

 
}


