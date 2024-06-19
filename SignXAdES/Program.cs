using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using GostCryptography.Xml;

class Program
{
    public static void SignXml(string xmlFilePath, byte[] certificateData, string certificatePassword)
    {
        XmlDocument xmlDoc = new XmlDocument();

        xmlDoc.PreserveWhitespace = true;
        xmlDoc.Load(xmlFilePath);

        X509Certificate2 certificate = new X509Certificate2(certificateData, certificatePassword);

        var signedXml = new GostSignedXml(xmlDoc);
        var privateKey = certificate.GetPrivateKeyAlgorithm();
        signedXml.SigningKey = privateKey;

        Reference reference = new Reference();

        reference.Uri = "";
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigC14NTransform());
        reference.DigestMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
        signedXml.AddReference(reference);

        KeyInfo keyInfo = new KeyInfo();

        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signedXml.KeyInfo = keyInfo;
        signedXml.ComputeSignature();

        XmlElement xmlDigitalSignature = signedXml.GetXml();

        xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
        xmlDoc.Save("./Certs/Signed_XML.xml");

        Console.WriteLine("Документ подписан");
    }

    public static void Main(string[] args)
    {
        string xmlFilePath = "./Certs/tosign.xml";
        byte[] certificateData = System.IO.File.ReadAllBytes("./Certs/cert.pfx");
        string certificatePassword = System.IO.File.ReadAllText("./Certs/pass.txt");

        SignXml(xmlFilePath, certificateData, certificatePassword);

        Console.ReadKey();
    }
}