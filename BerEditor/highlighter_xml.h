#ifndef HIGHLIGHTERXML_H
#define HIGHLIGHTERXML_H

#include <QObject>
#include <QWidget>
#include <QSyntaxHighlighter>
#include <QRegularExpression>

class HighlighterXML : public QSyntaxHighlighter
{
    Q_OBJECT

public:
    HighlighterXML(QTextDocument *parent = nullptr, int idx = 1);

protected:
    void highlightBlock(const QString &text) override;

private:
    struct HighlightingRule
    {
        QRegularExpression pattern;
        QTextCharFormat format;
    };
    QVector<HighlightingRule> highlightingRules;

    QRegularExpression commentStartExpression;
    QRegularExpression commentEndExpression;

    QTextCharFormat keywordFormat;
    QTextCharFormat classFormat;
    QTextCharFormat singleLineCommentFormat;
    QTextCharFormat multiLineCommentFormat;
    QTextCharFormat quotationFormat;
    QTextCharFormat functionFormat;
};

#endif // HIGHLIGHTERXML_H
