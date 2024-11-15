#include <QTextDocument>
#include <QSyntaxHighlighter>

#include "highlighter_xml.h"

HighlighterXML::HighlighterXML(QTextDocument *parent, int idx)
    : QSyntaxHighlighter( parent )
{
    HighlightingRule rule;

    keywordFormat.setForeground(Qt::darkBlue);
    keywordFormat.setFontWeight(QFont::Bold);
    const QString keywordPatterns[] = {
        QStringLiteral("\\bBOOLEAN\\b"), QStringLiteral("\\bINTEGER\\b"), QStringLiteral("\\bNULL\\b"),
        QStringLiteral("\\bBIT_STRING\\b"), QStringLiteral("\\bOCTET_STRING\\b"), QStringLiteral("\\bNULL_TAG\\b"),
        QStringLiteral("\\bOBJECT_IDENTIFIER\\b"), QStringLiteral("\\bOBJ_DESCRIPTOR\\b"), QStringLiteral("\\bEXTERNAL\\b"),
        QStringLiteral("\\bREAL\\b"), QStringLiteral("\\bENUMERATED\\b"), QStringLiteral("\\bEMBEDDED_PDV\\b"),
        QStringLiteral("\\bUTF8_STRING\\b"), QStringLiteral("\\bSEQUENCE\\b"), QStringLiteral("\\bSET\\b"),
        QStringLiteral("\\bNUMERIC_STRING\\b"), QStringLiteral("\\bPRINTABLE_STRING\\b"), QStringLiteral("\\bT61_STRING\\b"),
        QStringLiteral("\\bVIDEO_TEX_STRING\\b"), QStringLiteral("\\bIA5_STRING\\b"), QStringLiteral("\\bUTC_TIME\\b"),
        QStringLiteral("\\bGENERALIZED_TIME\\b"), QStringLiteral("\\bGRAPHIC_STRING\\b"), QStringLiteral("\\bVISIBLE_STRING\\b"),
        QStringLiteral("\\bGENERAL_STRING\\b"), QStringLiteral("\\bUNIVERSAL_STRING\\b"), QStringLiteral("\\bBMP_STRING\\b")
    };
    for (const QString &pattern : keywordPatterns) {
        rule.pattern = QRegularExpression(pattern);
        rule.format = keywordFormat;
        highlightingRules.append(rule);
    }

    classFormat.setFontWeight(QFont::Bold);
    classFormat.setForeground(Qt::darkBlue);
    rule.pattern = QRegularExpression(QStringLiteral("\\bCONTEXT[_0-9]*\\b"));
    rule.format = classFormat;
    highlightingRules.append(rule);

#if 0
    quotationFormat.setForeground(Qt::darkGreen);
    rule.pattern = QRegularExpression(QStringLiteral("\".*\""));
    rule.format = quotationFormat;
    highlightingRules.append(rule);
#endif

#if 0
    functionFormat.setFontItalic(true);
    functionFormat.setForeground(Qt::blue);
    rule.pattern = QRegularExpression(QStringLiteral("\\b[A-Za-z0-9_]+(?=\\()"));
    rule.format = functionFormat;
    highlightingRules.append(rule);
#endif

#if 0
    singleLineCommentFormat.setForeground(Qt::red);
    rule.pattern = QRegularExpression(QStringLiteral("//[^\n]*"));
    rule.format = singleLineCommentFormat;
    highlightingRules.append(rule);
#endif

    multiLineCommentFormat.setForeground(Qt::red);

    commentStartExpression = QRegularExpression(QStringLiteral("/\\*"));
    commentEndExpression = QRegularExpression(QStringLiteral("\\*/"));
}

void HighlighterXML::highlightBlock(const QString &text)
{
    for (const HighlightingRule &rule : qAsConst(highlightingRules)) {
        QRegularExpressionMatchIterator matchIterator = rule.pattern.globalMatch(text);
        while (matchIterator.hasNext()) {
            QRegularExpressionMatch match = matchIterator.next();
            setFormat(match.capturedStart(), match.capturedLength(), rule.format);
        }
    }

    setCurrentBlockState(0);

    int startIndex = 0;
    if (previousBlockState() != 1)
        startIndex = text.indexOf(commentStartExpression);

    while (startIndex >= 0) {
        QRegularExpressionMatch match = commentEndExpression.match(text, startIndex);
        int endIndex = match.capturedStart();
        int commentLength = 0;
        if (endIndex == -1) {
            setCurrentBlockState(1);
            commentLength = text.length() - startIndex;
        } else {
            commentLength = endIndex - startIndex
                            + match.capturedLength();
        }
        setFormat(startIndex, commentLength, multiLineCommentFormat);
        startIndex = text.indexOf(commentStartExpression, startIndex + commentLength);
    }
}
