//using iText.Bouncycastle.Crypto;
//using iText.Bouncycastle.X509;
//using iText.Bouncycastleconnector;
//using iText.Commons.Actions.Contexts;
//using iText.Commons.Bouncycastle;
//using iText.Commons.Bouncycastle.Cert;
//using iText.Commons.Bouncycastle.Crypto;
//using iText.Kernel.Pdf;
//using iText.Signatures;
//using Org.BouncyCastle.Pkcs;
//using Org.BouncyCastle.X509;
//using System;
//using System.Security.Claims;
//using System.Security.Cryptography;
//using System.Security.Cryptography.X509Certificates;


//public class PdfSigner
//{
//    IExternalSignature _privateSignature;
//    IX509Certificate[] _signChain;

//    public PdfSigner(Stream privateKeyStream, string keyPassword)
//    {
//        var pks = new Pkcs12Store(privateKeyStream, keyPassword.ToCharArray());
//        string alias = null;
//        foreach (string tAlias in pks.Aliases)
//        {
//            if (pks.IsKeyEntry(tAlias))
//            {
//                alias = tAlias;
//                break;
//            }
//        }
//        var pk = pks.GetKey(alias).Key;
//        var ce = pks.GetCertificateChain(alias);
//        _signChain = new IX509Certificate[ce.Length];
//        for (int k = 0; k < ce.Length; ++k)
//            _signChain[k] = new X509CertificateBC(ce[k].Certificate);
//        _privateSignature = new PrivateKeySignature(new PrivateKeyBC(pk), "SHA-512");
//    }

//    public void SignPDF(Stream input, Stream output, PDFSignParameters p)
//    {
//        PdfReader reader = new PdfReader(input);
//        StampingProperties properties = new StampingProperties();
//        var signer = new iText.Signatures.PdfSigner(reader, output, properties);

//        PdfSignatureAppearance sap = signer.GetSignatureAppearance().SetReason(p.Reason).SetLocation(p.Location);
//        if (p.Image != null)
//        {
//            var img = iText.IO.Image.ImageDataFactory.Create(new BinaryReader(p.Image.Data).ReadBytes((int)p.Image.Data.Length));
//            sap.SetSignatureGraphic(img);
//            sap.SetLayer2Text(string.Empty);
//            sap.SetPageRect(new iText.Kernel.Geom.Rectangle(p.Image.X, p.Image.Y, img.GetWidth() / p.Image.WidthRatio, img.GetHeight() / p.Image.HeigthRatio));
//            sap.SetImage(img);
//        }

//        signer.SignDetached(_privateSignature, _signChain, null, null, null, 0, iText.Signatures.PdfSigner.CryptoStandard.CMS);
//    }
//}


//    /// <summary>
//    /// This <see cref="IExternalSignature"/> implementation is where you put all the code that needs
//    /// to access the API of your service provider. Obviously you can inject required extra information
//    /// in the constructor or via properties, and you can optimize this for multiple usages (e.g. by
//    /// retrieving the certificate chain only once).
//    /// </summary>
//    /// <seealso cref="SignWithIExternalSignature"/>
//    internal class ServiceSignature : IExternalSignature
//    {
//        public string GetDigestAlgorithmName()
//        {
//            return "SHA-256";
//        }

//        public string GetSignatureAlgorithmName()
//        {
//            return "RSA";
//        }

//        public ISignatureMechanismParams? GetSignatureMechanismParameters()
//        {
//            return null;
//        }

//        public X509CertificateBC[] GetChain()
//        {
//            // Replace this with your code that retrieves your certificate chain from your signature
//            // service.
//            return new X509CertificateBC[] {
//                    new X509CertificateBC(new X509Certificate(dummy.certificate.GetRawCertData()))
//                };
//        }

//    public byte[] Sign(Stream inputStream)
//    {
//        byte[] encodedSig = null;
//        iText.Signatures.PrivateKeySignature signature = new iText.Signatures.PrivateKeySignature(pk, "SHA256");
//        string digestAlgorithmName = signature.GetDigestAlgorithmName();

//        iText.Signatures.PdfPKCS7 sgn = new iText.Signatures.PdfPKCS7(null, chain, digestAlgorithmName, false);

//        byte[] hash = iText.Signatures.DigestAlgorithms.Digest(inputStream, digestAlgorithmName);
//        byte[] sh = sgn.GetAuthenticatedAttributeBytes(hash, PdfSigner.CryptoStandard.CMS, null, null);
//        byte[] extSignature = signature.Sign(sh);
//        sgn.SetExternalSignatureValue(signatureHash, null, signature.GetSignatureAlgorithmName());

//        encodedSig = sgn.GetEncodedPKCS7(hash, PdfSigner.CryptoStandard.CMS, null, null, null);

//        return encodedSig;
//    }

//    DummyRsaSigningMaterial dummy = new DummyRsaSigningMaterial();
//    }


//class a
//{
//public HashInfo[] ConvertHashToBase64(string[] filePaths, JsonData identityInfo, string uniqueId)
//{
//    SPWeb cWeb = SPContext.Current.Web;
//    List<HashInfo> hashInfos = new List<HashInfo>();

//    foreach (string filePath in filePaths)
//    {
//        var signInstance = new PAdESSignerClass();
//        signInstance.EmptySignature(signedPath, aWeb, identityInfo, uniqueId);
//        SPFile file = aWeb.GetFile(filePath);
//        var fileStream = signedFile.OpenBinary();

//        using (SHA256 sha256Hash = SHA256.Create())
//        {
//            byte[] hashBytes = sha256Hash.ComputeHash(fileStream);
//            string base64Hash = Convert.ToBase64String(hashBytes);

//            hashInfos.Add(new HashInfo
//            {
//                Hash = base64Hash,
//                UniqueId = file.UniqueId,
//                FileName = file.Name
//            });
//        }
//    }

//    return hashInfos.ToArray();
//}

//}

//public class PAdESSignerClass
//{
//    public void EmptySignature(string containerFilePath, SPWeb web, JsonData jsonData, string guidString)
//    {
//        SPFile file = web.GetFile(containerFilePath);
//        var cert = jsonData.cert;
//        string certificate = cert.certificates[0].ToString();
//        byte[] certificateBytes = Convert.FromBase64String(certificate);
//        X509Certificate2 xcertificate = new X509Certificate2(certificateBytes);
//        IBouncyCastleFactory FACTORY = BouncyCastleFactoryCreator.GetFactory();
//        IX509Certificate[] iTextCertificates2 = FACTORY.CreateX509CertificateParser().ReadAllCerts(xcertificate.GetRawCertData()).ToArray();

//        using (Stream fileStream = file.OpenBinaryStream())
//        {
//            using (MemoryStream memoryStream = new MemoryStream())
//            {
//                iText.Kernel.Pdf.PdfReader reader = new iText.Kernel.Pdf.PdfReader(fileStream);
//                PdfSigner signer = new PdfSigner(reader, memoryStream, new StampingProperties());
//                signer.GetSignatureAppearance().SetCertificate(iTextCertificates2[0]);
//                signer.SetFieldName(guidString);

//                iText.Signatures.IExternalSignatureContainer external = new ExternalBlankSignatureContainer(iText.Kernel.Pdf.PdfName.Adobe_PPKLite,
//                iText.Kernel.Pdf.PdfName.Adbe_pkcs7_detached);

//                signer.SignExternalContainer(external, 8192);

//                byte[] pdfBytes = memoryStream.ToArray();
//                web.Files.Add(containerFilePath, pdfBytes, true);
//            }
//        }
//    }

//    public void AddSignatureToPdf(string certPath, JsonData jsonData, string containerFilePath, byte[] signatureHash, SPWeb web, string uniqueId, string timestamp)
//    {
//        var cert = jsonData.cert;
//        string certificate = cert.certificates[0].ToString();
//        byte[] certificateBytes = Convert.FromBase64String(certificate);

//        SPFile file = web.GetFile(containerFilePath);

//        using (Stream fileStream = file.OpenBinaryStream())
//        {
//            using (MemoryStream memoryStream = new MemoryStream())
//            {
//                iText.Kernel.Pdf.PdfReader pdfDoc = new iText.Kernel.Pdf.PdfReader(fileStream);
//                PdfSigner signer = new PdfSigner(pdfDoc, memoryStream, new iText.Kernel.Pdf.StampingProperties());

//                X509Certificate2 xcertificate = new X509Certificate2(certificateBytes);

//                IBouncyCastleFactory FACTORY = BouncyCastleFactoryCreator.GetFactory();
//                IX509Certificate[] iTextCertificates2 = FACTORY.CreateX509CertificateParser().ReadAllCerts(xcertificate.GetRawCertData()).ToArray();
//                IPrivateKey iTextPrivateKey = FACTORY.CreateRsa2048KeyPairGenerator().GenerateKeyPair().GetPrivateKey();

//                signer.GetSignatureAppearance();

//                iText.Signatures.IExternalSignatureContainer external = new MyExternalSignatureContainer(iTextPrivateKey, iTextCertificates2, signatureHash, certificateBytes, timestamp);

//                PdfSigner.SignDeferred(signer.GetDocument(), uniqueId, memoryStream, external);

//                byte[] signedBytes = memoryStream.ToArray();
//                web.Files.Add(containerFilePath, signedBytes, true);
//            }
//        }
//    }
//}

//public class MyExternalSignatureContainer : iText.Signatures.IExternalSignatureContainer
//{
//    private readonly byte[] signedBytes;
//    protected IPrivateKey pk;
//    protected IX509Certificate[] chain;
//    protected byte[] signatureHash;
//    protected byte[] certificateBytes;
//    protected string timestamp;

//    public MyExternalSignatureContainer(IPrivateKey pk, IX509Certificate[] chain, byte[] signatureHash, byte[] certificateBytes, string timestamp)
//    {
//        this.pk = pk;
//        this.chain = chain;
//        this.signatureHash = signatureHash;
//        this.certificateBytes = certificateBytes;
//        this.timestamp = timestamp;
//    }

//    public void ModifySigningDictionary(iText.Kernel.Pdf.PdfDictionary signDic)
//    {
//    }

//    public byte[] Sign(Stream inputStream)
//    {
//        byte[] encodedSig = null;
//        iText.Signatures.PrivateKeySignature signature = new iText.Signatures.PrivateKeySignature(pk, "SHA256");
//        string digestAlgorithmName = signature.GetDigestAlgorithmName();

//        iText.Signatures.PdfPKCS7 sgn = new iText.Signatures.PdfPKCS7(null, chain, digestAlgorithmName, false);

//        byte[] hash = iText.Signatures.DigestAlgorithms.Digest(inputStream, digestAlgorithmName);
//        byte[] sh = sgn.GetAuthenticatedAttributeBytes(hash, PdfSigner.CryptoStandard.CMS, null, null);
//        byte[] extSignature = signature.Sign(sh);
//        sgn.SetExternalSignatureValue(signatureHash, null, signature.GetSignatureAlgorithmName());

//        encodedSig = sgn.GetEncodedPKCS7(hash, PdfSigner.CryptoStandard.CMS, null, null, null);

//        return encodedSig;
//    }
//}










