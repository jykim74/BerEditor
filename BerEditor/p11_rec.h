#ifndef P11REC_H
#define P11REC_H

#include <QString>

class P11Rec
{
    long        mHandle;
    QString     mLabel;

public:
    P11Rec();

    long getHandle() { return mHandle; };
    const QString getLabel() { return mLabel; };

    void setHandle( long hHandle );
    void setLabel( const QString strLabel );
};

#endif // P11REC_H
