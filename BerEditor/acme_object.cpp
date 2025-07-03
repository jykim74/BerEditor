#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "acme_object.h"

ACMEObject::ACMEObject(QObject *parent)
    : QObject{parent}
{

}

void ACMEObject::setProtected( const QString strProtected )
{
    mProtected = strProtected;
}

void ACMEObject::setPayload( const QString strPayload )
{
    mPayload = strPayload;
}

void ACMEObject::setSignature( const QString strSignature )
{
    mSignature = strSignature;
}

const QString ACMEObject::getJson()
{
    QJsonDocument jDoc;
    QJsonObject jObj;
    QJsonObject jPayload;
    QJsonObject jSignature;

    jObj["protected"] = mProtected;
    jObj["payload"] = mPayload;
    jObj["signature"] = mSignature;

    jDoc.setObject( jObj );

    return jDoc.toJson();
}
