#include "pdf_object.h"
#include "podofo/podofo.h"

using namespace PoDoFo;

PDFObject::PDFObject() {}

void PDFObject::test()
{
    /*
    PdfMemDocument doc(inputPdf.c_str());
    PdfAcroForm* form = doc.GetAcroForm();

    if (!form) {
        form = doc.CreateAcroForm();
    }

    PdfPage* page = doc.GetPage(0);
    PdfRect rect(100.0, 100.0, 200.0, 50.0);

    // 서명 필드 생성
    PdfAnnotation* annot = page->CreateAnnotation(PdfAnnotation::AnnotationType_Widget, rect);
    PdfField* sigField = form->CreateSignatureField("Signature1", annot);
    sigField->GetObject()->GetDictionary().AddKey("FT", PdfName("Sig"));
    sigField->GetObject()->GetDictionary().AddKey("T", PdfString("Signature1"));

    // 빈 /Contents 예약
    PdfObject* sigObj = new PdfObject();
    sigObj->GetDictionary().AddKey("Type", PdfName("Sig"));
    sigObj->GetDictionary().AddKey("Filter", PdfName("Adobe.PPKLite"));
    sigObj->GetDictionary().AddKey("SubFilter", PdfName("adbe.pkcs7.detached"));
    sigObj->GetDictionary().AddKey("Contents", PdfString(std::string(8192, 0))); // 서명 공간 확보
    sigField->GetObject()->GetDictionary().AddKey("V", PdfReference(doc.GetObjects().AddObject(sigObj)));

    doc.Write(outputPdf.c_str());
    */
}
