#include "p11_rec.h"

P11Rec::P11Rec()
{

}

void P11Rec::setHandle( long hHandle )
{
    mHandle = hHandle;
}

void P11Rec::setLabel( const QString strLabel )
{
    mLabel = strLabel;
}

void P11Rec::setKeyType( long nKeyType )
{
    mKeyType = nKeyType;
}

void P11Rec::setID( const QString strID )
{
    mID = strID;
}

void P11Rec::setValue( const QString strValue )
{
    mValue = strValue;
}
