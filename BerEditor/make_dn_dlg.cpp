/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QAction>
#include <QMenu>

#include <QStringList>

#include "make_dn_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "common.h"

const QStringList kRDNList = {
    "emailAddress", "CN", "OU", "O",
    "L", "ST", "C"
};

MakeDNDlg::MakeDNDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mRDNTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotTableMenuRequested(QPoint)));

    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mEmailAddressText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mCNText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mOText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mOUText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mLText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mSTText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mCText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mRDNAddBtn, SIGNAL(clicked()), this, SLOT(clickRDNAdd()));

    mOKBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

MakeDNDlg::~MakeDNDlg()
{

}

void MakeDNDlg::initUI()
{
    mRDNNameCombo->setEditable(true);
    mRDNNameCombo->addItems( kRDNList );

    mEmailAddressText->setPlaceholderText( "Email" );
    mCNText->setPlaceholderText( "Common Name" );
    mOUText->setPlaceholderText( "Organization Unit" );
    mOText->setPlaceholderText( "Organization" );
    mLText->setPlaceholderText( "Locality" );
    mSTText->setPlaceholderText( "State/Province" );
    mCText->setPlaceholderText( "Country" );


    QStringList sBaseLabels = { tr("Name"), tr("Value") };

    mRDNTable->clear();
    mRDNTable->horizontalHeader()->setStretchLastSection(true);
    mRDNTable->setColumnCount(sBaseLabels.size());
    mRDNTable->setHorizontalHeaderLabels( sBaseLabels );
    mRDNTable->verticalHeader()->setVisible(false);
    mRDNTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mRDNTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mRDNTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mRDNTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void MakeDNDlg::initialize()
{
    mCNText->setFocus();
}

void MakeDNDlg::setDN( const QString strDN )
{
    QStringList strList = strDN.split( "," );

    for( int i = 0; i < strList.size(); i++ )
    {
        QString strPart = strList.at(i);
        QStringList strNVList = strPart.split( "=" );
        if( strNVList.size() != 2 ) continue;

        QString strName = strNVList.at(0);
        QString strValue = strNVList.at(1);

        if( strName == "CN" )
        {
            if( mCNText->text().length() < 1)
                mCNText->setText( strValue );
            else
                appendRDNTable( strName, strValue );
        }
        else if( strName.toUpper() == "EMAILADDRESS" )
        {
            if( mEmailAddressText->text().length() < 1 )
                mEmailAddressText->setText( strValue );
            else
                appendRDNTable( strName, strValue );
        }
        else if( strName == "O" )
        {
            if( mOText->text().length() < 1 )
                mOText->setText( strValue );
            else
                appendRDNTable( strName, strValue );
        }
        else if( strName == "OU" )
        {
            if( mOUText->text().length() < 1)
                mOUText->setText( strValue );
            else
                appendRDNTable( strName, strValue );
        }
        else if( strName == "L" )
        {
            if( mLText->text().length() < 1 )
                mLText->setText( strValue );
            else
                appendRDNTable( strName, strValue );
        }
        else if( strName == "ST" )
        {
            if( mSTText->text().length() < 1 )
                mSTText->setText( strValue );
            else
                appendRDNTable( strName, strValue );
        }
        else if( strName == "C" )
        {
            if( mCText->text().length() < 1 )
                mCText->setText( strValue );
            else
                appendRDNTable( strName, strValue );
        }
        else
        {
            appendRDNTable( strName, strValue );
        }

        changeDN();
    }
}

const QString MakeDNDlg::getDN()
{
    QString strEmailAddress = mEmailAddressText->text();
    QString strCN = mCNText->text();
    QString strO = mOText->text();
    QString strOU = mOUText->text();
    QString strL = mLText->text();
    QString strST = mSTText->text();
    QString strC = mCText->text();


    QString strRDN_Email;
    QString strRDN_CN;
    QString strRDN_OU;
    QString strRDN_O;
    QString strRDN_L;
    QString strRDN_ST;
    QString strRDN_C;
    QString strRDN_More;


    QString strDN;

    if( strEmailAddress.length() > 0 )
    {
        strRDN_Email = QString( "emailAddress=%1").arg(strEmailAddress);
    }

    if( strCN.length() > 0 )
    {
        strRDN_CN = QString( "CN=%1").arg( strCN );
    }

    if( strOU.length() > 0 )
    {
        strRDN_OU = QString( "OU=%1").arg( strOU );
    }

    if( strO.length() > 0 )
    {
        strRDN_O = QString( "O=%1").arg( strO );
    }

    if( strL.length() > 0 )
    {
        strRDN_L = QString( "L=%1").arg( strL );
    }

    if( strST.length() > 0 )
    {
        strRDN_ST = QString( "ST=%1").arg( strST );
    }

    if( strC.length() > 0 )
    {
        strRDN_C = QString( "C=%1" ).arg( strC );
    }

    int nCount = mRDNTable->rowCount();

    for( int i = 0; i < nCount; i++ )
    {
        QTableWidgetItem *item0 = mRDNTable->item(i, 0);
        QTableWidgetItem *item1 = mRDNTable->item(i, 1);

        QString strName = item0->text();
        QString strValue = item1->text();

        if( strName == "emailAddress" )
        {
            if( strRDN_Email.length() > 0 ) strRDN_Email += ",";
            strRDN_Email += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "CN" )
        {
            if( strRDN_CN.length() > 0 ) strRDN_CN += ",";
            strRDN_CN += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "OU" )
        {
            if( strRDN_OU.length() > 0 ) strRDN_OU += ",";
            strRDN_OU += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "O" )
        {
            if( strRDN_O.length() > 0 ) strRDN_O += ",";
            strRDN_O += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "L" )
        {
            if( strRDN_L.length() > 0 ) strRDN_L += ",";
            strRDN_L += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "ST" )
        {
            if( strRDN_ST.length() > 0 ) strRDN_ST += ",";
            strRDN_ST += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "C" )
        {
            if( strRDN_C.length() > 0 ) strRDN_C += ",";
            strRDN_C += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else
        {
            if( strRDN_More.length() > 0 ) strRDN_More += ",";
            strRDN_More += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
    }

    if( strRDN_More.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_More;
    }

    if( strRDN_Email.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_Email;
    }

    if( strRDN_CN.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_CN;
    }

    if( strRDN_OU.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_OU;
    }

    if( strRDN_O.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_O;
    }

    if( strRDN_L.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_L;
    }

    if( strRDN_ST.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_ST;
    }

    if( strRDN_C.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_C;
    }


    return strDN;
}

void MakeDNDlg::slotTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction* deleteAct = new QAction( tr( "Delete" ), this );

    connect( deleteAct, SIGNAL(triggered()), this, SLOT(deleteRDN()));

    menu->addAction( deleteAct );
    menu->popup( mRDNTable->viewport()->mapToGlobal(pos));
}

void MakeDNDlg::clickOK()
{
    QString strDN = getDN();

    if( strDN.length() < 3 )
    {
        berApplet->warningBox( tr( "Enter DN value" ), this );
        mCNText->setFocus();
        return;
    }

    accept();
}

void MakeDNDlg::clickClear()
{
    mEmailAddressText->clear();
    mCNText->clear();
    mOText->clear();
    mOUText->clear();
    mSTText->clear();
    mCText->clear();
    mLText->clear();

    mRDNValueText->clear();
    mRDNTable->setRowCount(0);
}

void MakeDNDlg::changeDN()
{
    QString strDN = getDN();
    mDNText->setText( strDN );
}

void MakeDNDlg::clickRDNAdd()
{
    QString strName = mRDNNameCombo->currentText();
    QString strValue = mRDNValueText->text();

    if( strName.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a name" ), this );
        mRDNNameCombo->setFocus();
        return;
    }

    if( strValue.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a value" ), this );
        mRDNValueText->setFocus();
        return;
    }

    mRDNTable->insertRow(0);
    mRDNTable->setRowHeight(0, 10);
    mRDNTable->setItem( 0, 0, new QTableWidgetItem( strName ));
    mRDNTable->setItem( 0, 1, new QTableWidgetItem( strValue ));

    mRDNValueText->clear();
    changeDN();
}

void MakeDNDlg::deleteRDN()
{
    QModelIndex idx = mRDNTable->currentIndex();
    QTableWidgetItem* item = mRDNTable->item( idx.row(), 0 );

    if( item )
    {
        mRDNTable->removeRow( idx.row() );
        changeDN();
    }
}

void MakeDNDlg::appendRDNTable( const QString strName, const QString strValue )
{
    int nCount = mRDNTable->rowCount();

    mRDNTable->insertRow( nCount);
    mRDNTable->setRowHeight(nCount, 10);
    mRDNTable->setItem( nCount, 0, new QTableWidgetItem( strName ));
    mRDNTable->setItem( nCount, 1, new QTableWidgetItem( strValue ));
}
