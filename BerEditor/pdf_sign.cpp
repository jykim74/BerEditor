#include <iostream>
#include <cstdio>
#include <fstream>

#include "podofo/podofo.h"
#include "pdf_sign.h"

PDFSign::PDFSign()
{

}

int PDFSign::readFile( const QString strPath )
{
    PdfMemDocument doc;
    doc.Load( strPath.toStdString().c_str() );


    return 0;
}

void PDFSign::test()
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

#define CONVERSION_CONSTANT 0.002834645669291339

void PDFSign::CreateSimpleForm( PdfPage* pPage, PdfStreamedDocument* pDoc, const PdfData &signatureData )
{
    /*
    PdfPainter painter;
    PdfFont*   pFont = pDoc->CreateFont( "Courier" );

    painter.SetPage( pPage );
    painter.SetFont( pFont );
    painter.DrawText( 10000 * CONVERSION_CONSTANT, 280000 * CONVERSION_CONSTANT, "PoDoFo Sign Test" );
    painter.FinishPage();

    PdfSignatureField signField( pPage, PdfRect( 70000 * CONVERSION_CONSTANT, 10000 * CONVERSION_CONSTANT,
                                               50000 * CONVERSION_CONSTANT, 50000 * CONVERSION_CONSTANT ), pDoc );
    signField.SetFieldName("SignatureFieldName");
    signField.SetSignature(signatureData);
    signField.SetSignatureReason("I agree");
    */
}

