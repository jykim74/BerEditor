#include <QStringList>

#include "revoke_reason_dlg.h"

const QStringList kReasonList = {
    "unspecified",
    "keyCompromise",
    "CACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "removeFromCRL",
    /* Additional pseudo reasons */
    "holdInstruction",
    "keyTime",
    "CAkeyTime"
};

RevokeReasonDlg::RevokeReasonDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mReasonCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeReason(int)));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

RevokeReasonDlg::~RevokeReasonDlg()
{

}

void RevokeReasonDlg::initUI()
{
    mReasonCombo->addItems( kReasonList );
}

void RevokeReasonDlg::clickOK()
{
    accept();
}

void RevokeReasonDlg::changeReason( int index )
{
    mReasonText->setText( QString("%1").arg(index));
}
