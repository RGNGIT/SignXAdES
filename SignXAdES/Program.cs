using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using CryptoPro.Sharpei.Xml;

namespace Directum
{
    class SignDocument
    {
        [STAThread]
        static void Main(string[] args)
        {
            try
            {
                X509Certificate2Collection found;

                X509Store store = new X509Store(StoreLocation.LocalMachine);
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                found = store.Certificates.Find(X509FindType.FindByThumbprint, System.IO.File.ReadAllText("./Certs/thumbprint.txt").Trim(' '), false);

                if (found.Count == 0)
                {
                    store = new X509Store(StoreLocation.CurrentUser);
                    store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                    found = store.Certificates.Find(X509FindType.FindByThumbprint, System.IO.File.ReadAllText("./Certs/thumbprint.txt").Trim(' '), false);
                }

                if (found.Count == 0)
                    throw new Exception("Сертификат не найден.");

                X509Certificate2 Certificate = found[0];

                AsymmetricAlgorithm Key = Certificate.PrivateKey;
                SignXmlFile("./Certs/tosign.xml", "./Certs/signed.xml", Key, Certificate);
                Console.WriteLine("XML подписан.");
            }
            catch (Exception ex) 
            {
                Console.WriteLine(ex.Message);
            }
            Console.ReadKey();
        }

        // Подписываем XML файл и сохраняем его в новом файле.
        static void SignXmlFile(string FileName,
            string SignedFileName, AsymmetricAlgorithm Key,
            X509Certificate Certificate)
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load(new XmlTextReader(FileName));

            SignedXml signedXml = new SignedXml(doc);
            signedXml.SigningKey = Key;

            Reference reference = new Reference();
            reference.Uri = "";
            reference.DigestMethod = CPSignedXml.XmlDsigGost3411Url;


            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            XmlDsigSmevTransform smev = new XmlDsigSmevTransform(); 
            reference.AddTransform(smev);

            XmlDsigC14NTransform c14 = new XmlDsigC14NTransform();
            reference.AddTransform(c14);
            signedXml.AddReference(reference);

            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(Certificate));
            signedXml.KeyInfo = keyInfo;
            signedXml.ComputeSignature();

            XmlElement xmlDigitalSignature = signedXml.GetXml();
            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));

            if (doc.FirstChild is XmlDeclaration)
            {
                doc.RemoveChild(doc.FirstChild);
            }

            using (XmlTextWriter xmltw = new XmlTextWriter(SignedFileName,
                new UTF8Encoding(false)))
            {
                xmltw.WriteStartDocument();
                doc.WriteTo(xmltw);
            }
        }
    }
}
