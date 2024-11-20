#ifndef P11REC_H
#define P11REC_H

#include <QString>

class P11Rec
{
    long        mHandle;
    QString     mLabel;
    long        mKeyType;
    QString     mID;
    QString     mValue;

public:
    P11Rec();

    long getHandle() { return mHandle; };
    const QString getLabel() { return mLabel; };
    long getKeyType() { return mKeyType; };
    const QString getID() { return mID; };
    const QString getValue() { return mValue; };

    void setHandle( long hHandle );
    void setLabel( const QString strLabel );
    void setKeyType( long nKeyType );
    void setID( const QString strID );
    void setValue( const QString strValue );
};

#endif // P11REC_H
