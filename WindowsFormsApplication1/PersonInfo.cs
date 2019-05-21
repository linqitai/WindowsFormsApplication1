using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace WindowsFormsApplication1
{
    public class PersonInfo
    {
        public PersonInfo() { }
        public PersonInfo(string accessNumber,  string pwd, string name, string sex, string nation, string credentialsNumber, string credentialsType, string address,
            string issuingAuthority, string expiryDate, string company, string tempAddress, string contactInformation, string collectionSite, string collectionMode,
            string collectionType, string credentialsPhotoType, string credentialsPhoto, string photograph, string _operator, string submissionType, string personnelID,
            string credentialsPhotoID, string photographID, string personnelType,string policestation, string community, string brithday) {
                this.accessNumber = accessNumber;
                this.name = name;

        }
        private string accessNumber;

        public string AccessNumber
        {
            get { return accessNumber; }
            set { accessNumber = value; }
        }
        private string pwd;

        public string Pwd
        {
            get { return pwd; }
            set { pwd = value; }
        }
        private string name;

        public string Name
        {
            get { return name; }
            set { name = value; }
        }
        private string sex;

        public string Sex
        {
            get { return sex; }
            set { sex = value; }
        }
        private string nation;

        public string Nation
        {
            get { return nation; }
            set { nation = value; }
        }
        private string credentialsNumber;

        public string CredentialsNumber
        {
            get { return credentialsNumber; }
            set { credentialsNumber = value; }
        }
        private string credentialsType;

        public string CredentialsType
        {
            get { return credentialsType; }
            set { credentialsType = value; }
        }
        private string address;

        public string Address
        {
            get { return address; }
            set { address = value; }
        }
        private string issuingAuthority;

        public string IssuingAuthority
        {
            get { return issuingAuthority; }
            set { issuingAuthority = value; }
        }
        private string expiryDate;

        public string ExpiryDate
        {
            get { return expiryDate; }
            set { expiryDate = value; }
        }
        private string company;

        public string Company
        {
            get { return company; }
            set { company = value; }
        }
        private string tempAddress;

        public string TempAddress
        {
            get { return tempAddress; }
            set { tempAddress = value; }
        }
        private string contactInformation;

        public string ContactInformation
        {
            get { return contactInformation; }
            set { contactInformation = value; }
        }
        private string collectionSite;

        public string CollectionSite
        {
            get { return collectionSite; }
            set { collectionSite = value; }
        }
        private string collectionMode;

        public string CollectionMode
        {
            get { return collectionMode; }
            set { collectionMode = value; }
        }
        private string collectionType;

        public string CollectionType
        {
            get { return collectionType; }
            set { collectionType = value; }
        }
        private string credentialsPhotoType;

        public string CredentialsPhotoType
        {
            get { return credentialsPhotoType; }
            set { credentialsPhotoType = value; }
        }
        private string credentialsPhoto;

        public string CredentialsPhoto
        {
            get { return credentialsPhoto; }
            set { credentialsPhoto = value; }
        }
        private string photograph;

        public string Photograph
        {
            get { return photograph; }
            set { photograph = value; }
        }
        private string _operator;

        public string _operator1
        {
            get { return _operator; }
            set { _operator = value; }
        }
        private string submissionType;

        public string SubmissionType
        {
            get { return submissionType; }
            set { submissionType = value; }
        }
        private string personnelID;

        public string PersonnelID
        {
            get { return personnelID; }
            set { personnelID = value; }
        }
        private string credentialsPhotoID;

        public string CredentialsPhotoID
        {
            get { return credentialsPhotoID; }
            set { credentialsPhotoID = value; }
        }
        private string photographID;

        public string PhotographID
        {
            get { return photographID; }
            set { photographID = value; }
        }
        private string personnelType;

        public string PersonnelType
        {
            get { return personnelType; }
            set { personnelType = value; }
        }
        private string policestation;

        public string Policestation
        {
            get { return policestation; }
            set { policestation = value; }
        }
        
        private string community;

        public string Community
        {
            get { return community; }
            set { community = value; }
        }
        private string brithday;

        public string Brithday
        {
            get { return brithday; }
            set { brithday = value; }
        }
    }
}
