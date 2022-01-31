using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

/*
 'Required Imports

Imports System.Security.Cryptography.Pkcs
Imports System.Text
Imports System.Security.Cryptography.X509Certificates

'CONSOLE ENTRY POINT
Sub Main()

    'SIGNER PART, TAKE SOME PLAIN TEXT AND SIGN IT

    'Simple text to sign
    Dim textToSign As String = "hello world"

    'Convert to array of bytes
    Dim contentInfo As New ContentInfo(Encoding.UTF8.GetBytes(textToSign))

    'New signedCMS object to perform the work
    Dim signedCms As New SignedCms(contentInfo, True)

    'Read the *.PFX file from disk  and specifi the password you used to export it
    Dim certificateFromFile = _
       New X509Certificate2("C:\my certificate.pfx", "The password I Used")

    'Signer guy based on the certificate
    Dim Signer As CmsSigner = New CmsSigner(certificateFromFile)

    'Sign the content and keep it inside signedCMS object
    signedCms.ComputeSignature(Signer)

    'Encode signed data to extract it
    Dim encodedMessage As Byte() = signedCms.Encode()

    'To store in a file or Database get the string representation of signed data
    Dim signedDataInText = Convert.ToBase64String(encodedMessage)


    'SECOND PART, RECEIVE SIGNED DATA AND CHECK WITH THE ORIGINAL MESSAGE

    Dim originalTextToSign As String = "hello world"

    Dim contentInfo2 As New ContentInfo(Encoding.UTF8.GetBytes(originalTextToSign))

    Dim signedCms2 As New SignedCms(contentInfo2, True)

    'take signed string representation and convert to byte array to perform decode
    Dim encodedMessageFromSender As Byte() = Convert.FromBase64String(signedDataInText)

    signedCms2.Decode(encodedMessageFromSender)

    'Check the original message against the encrypted hash
    'If something is wrong this line will cause an exception
    signedCms2.CheckSignature(True)

End Sub
 
 */
namespace ConsoleApp2
{
    public class WorkerUtil
    {


        private static X509Certificate2 GetCertificateFromStore(string certName)
        {

            // Get the certificate store for the current user.
            X509Store store = new X509Store(StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                // Place all certificates in an X509Certificate2Collection object.
                X509Certificate2Collection certCollection = store.Certificates;
                // If using a certificate with a trusted root you do not need to FindByTimeValid, instead:
                // currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
                X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection signingCert = currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, false);
                //if (signingCert.Count == 0)
                //    return null;
                // Return the first certificate in the collection, has the right name and is current.
                // return signingCert[0];
                return currentCerts[0];
            }
            finally
            {
                store.Close();
            }
        }




        public static void Test() 
        {

           // 'SIGNER PART, TAKE SOME PLAIN TEXT AND SIGN IT

   // 'Simple text to sign
    var textToSign  = "hello world";

            //  'Convert to array of bytes
         
            var contentInfo = new ContentInfo(Encoding.UTF8.GetBytes(textToSign));

   // 'New signedCMS object to perform the work
    var signedCms = new SignedCms(contentInfo, true);

            // 'Read the *.PFX file from disk  and specifi the password you used to export it
          //  var certificateFromFile = new X509Certificate2(@"C:\my certificate.pfx", "The password I Used");

            // 'Signer guy based on the certificate
            var cert =   GetCertificateFromStore(null);
            var Signer = new CmsSigner(cert);   //new CmsSigner(certificateFromFile);

            // 'Sign the content and keep it inside signedCMS object
            signedCms.ComputeSignature(Signer);

            // 'Encode signed data to extract it
            var encodedMessage = signedCms.Encode();

            // 'To store in a file or Database get the string representation of signed data
            var signedDataInText = Convert.ToBase64String(encodedMessage);


   // 'SECOND PART, RECEIVE SIGNED DATA AND CHECK WITH THE ORIGINAL MESSAGE

            var originalTextToSign = "hello world";

            var contentInfo2 = new ContentInfo(Encoding.UTF8.GetBytes(originalTextToSign));

    var signedCms2 = new SignedCms(contentInfo2, true);

            // 'take signed string representation and convert to byte array to perform decode
            var encodedMessageFromSender = Convert.FromBase64String(signedDataInText);

            signedCms2.Decode(encodedMessageFromSender);


            signedCms2.CheckSignature(true);


        }
    }
}
