#include "pdf_object.h"
#include "podofo/podofo.h"

using namespace PoDoFo;

PDFObject::PDFObject() {}

void PDFObject::test()
{
    // X509 Certificate
    /*
    string cert;
    TestUtils::ReadTestInputFile("mycert.der", cert);

    PdfMemDocument doc(stream);
    auto& page = doc.GetPages().GetPageAt(0);
    auto& annot = page.GetAnnotations().GetAnnotAt(0);
    auto& field = dynamic_cast<PdfAnnotationWidget&>(annot).GetField();
    auto& signature = dynamic_cast<PdfSignature&>(field);

    auto signer = PdfSignerCms(cert, pkey);
    PoDoFo::SignDocument(doc, *stream, signer, signature, PdfSaveOptions::NoMetadataUpdate);
    */
}
