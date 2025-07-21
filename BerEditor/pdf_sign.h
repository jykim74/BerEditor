#ifndef PDFSIGN_H
#define PDFSIGN_H

#include <QObject>
#include "podofo/podofo.h"

using namespace std;
using namespace PoDoFo;

class PDFSign
{
public:
    PDFSign();

    int readFile( const QString strPath );
    void test();

    void CreateSimpleForm( PdfPage* pPage, PdfStreamedDocument* pDoc, const PdfData &signatureData );
};

#endif // PDFSIGN_H
