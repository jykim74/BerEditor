#ifndef ACME_OBJECT_H
#define ACME_OBJECT_H

#include <QObject>

class ACMEObject : public QObject
{
    Q_OBJECT
public:
    explicit ACMEObject(QObject *parent = nullptr);

    const QString getProtected() { return mProtected; };
    const QString getPayload() { return mPayload; };
    const QString getSignature() { return mSignature; };

    void setProtected( const QString strProtected );
    void setPayload( const QString strPayload );
    void setSignature( const QString strSignature );

    const QString getJson();

private:
    QString mProtected;
    QString mPayload;
    QString mSignature;
};

#endif // ACME_OBJECT_H
