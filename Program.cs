using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

string KEYSTORE = "D:\\resources\\cert.pfx";
char[] PASSWORD = "SEKRETNEHASLO".ToCharArray();
string DEST = "D:\\resources\\SignedPDF.pdf";
string SRC = "D:\\resources\\SampleContract.pdf";

Pkcs12Store pk12 = new (new FileStream(KEYSTORE,
FileMode.Open, FileAccess.Read), PASSWORD);
string alias = string.Empty;
foreach (object a in pk12.Aliases)
{
    alias = ((string)a);
    if (pk12.IsKeyEntry(alias))
    {
        break;
    }
}
ICipherParameters pk = pk12.GetKey(alias).Key;

X509CertificateEntry[] ce = pk12.GetCertificateChain(alias);
X509Certificate[] chain = new X509Certificate[ce.Length];
for (int k = 0; k < ce.Length; ++k)
{
    chain[k] = ce[k].Certificate;
}


PdfReader reader = new (SRC);
PdfSigner signer = new (reader,new FileStream(DEST, FileMode.Create),new StampingProperties());

PdfSignatureAppearance appearance = signer.GetSignatureAppearance();
appearance.SetReason("My reason to sign...")
    .SetLocation("Lahore")
    .SetPageRect(new Rectangle(36, 648, 200, 100))
    .SetPageNumber(1);
signer.SetFieldName("MyFieldName");



IExternalSignature pks = new PrivateKeySignature((iText.Commons.Bouncycastle.Crypto.IPrivateKey)pk, DigestAlgorithms.SHA256);

    signer.SignDetached(pks, (iText.Commons.Bouncycastle.Cert.IX509Certificate[])chain, null, null, null, 0,
PdfSigner.CryptoStandard.CMS);

