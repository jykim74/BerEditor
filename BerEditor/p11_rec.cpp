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
