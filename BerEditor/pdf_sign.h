#ifndef PDFSIGN_H
#define PDFSIGN_H

#include <QObject>

class PDFSign
{
public:
    PDFSign();

    int readFile( const QString strPath );
    void test();
};

#endif // PDFSIGN_H
