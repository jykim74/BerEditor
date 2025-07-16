#include <QSettings>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "doc_signer_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "common.h"
#include "acme_tree_dlg.h"
#include "acme_object.h"

DocSignerDlg::DocSignerDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked(bool)), this, SLOT(close()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));

    connect( mJSONComputeSignatureBtn, SIGNAL(clicked()), this, SLOT(clickJSON_ComputeSignature()));
    connect( mJSONVerifySignatureBtn, SIGNAL(clicked()), this, SLOT(clickJSON_VerifySignature()));
    connect( mJSONPayloadClearBtn, SIGNAL(clicked()), this, SLOT(clickJSON_PayloadClear()));
    connect( mJSONPayloadViewBtn, SIGNAL(clicked()), this, SLOT(clickJSON_PayloadView()));
    connect( mJSON_JWSClearBtn, SIGNAL(clicked()), this, SLOT(clickJSON_JWKClear()));
    connect( mJSON_JWSViewBtn, SIGNAL(clicked()), this, SLOT(clickJSON_JWKView()));
}

DocSignerDlg::~DocSignerDlg()
{

}

void DocSignerDlg::clickClearAll()
{

}

void DocSignerDlg::clickJSON_ComputeSignature()
{

}

void DocSignerDlg::clickJSON_VerifySignature()
{

}

void DocSignerDlg::clickJSON_PayloadClear()
{

}

void DocSignerDlg::clickJSON_JWKClear()
{

}

void DocSignerDlg::clickJSON_PayloadView()
{

}

void DocSignerDlg::clickJSON_JWKView()
{

}
