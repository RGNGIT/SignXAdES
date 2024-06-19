using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using GostCryptography.Xml;

class Program
{
    public static void SignXml(string xmlFilePath, string certificateThumbprint)
    {
        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.PreserveWhitespace = true;
        xmlDoc.Load(xmlFilePath);

        X509Certificate2 certificate = GetCertificateByThumbprint(certificateThumbprint);

        var signedXml = new GostSignedXml(xmlDoc);
        signedXml.SigningKey = certificate.GetRSAPrivateKey();

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

    public static X509Certificate2 GetCertificateByThumbprint(string thumbprint)
    {
        using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
        {
            store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (cert.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    return cert;
                }
            }
        }
        throw new Exception($"Certificate with thumbprint {thumbprint} not found");
    }

    public static void Main(string[] args)
    {
        string xmlFilePath = "./Certs/tosign.xml";
        string certificateThumbprint = "";

        SignXml(xmlFilePath, certificateThumbprint);

        Console.ReadKey();
    }
}