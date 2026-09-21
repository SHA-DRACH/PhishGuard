// Builds the PhishGuard project report (Chapters 1–6) as a .docx
const fs = require('fs');
const path = require('path');
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, Table, TableRow, TableCell,
  WidthType, BorderStyle, ShadingType, ImageRun, TableOfContents, Footer, PageNumber, LevelFormat,
  PageBreak, TabStopType,
} = require('docx');

const FIG = path.join(__dirname, '..', 'figures');
const FONT = 'Times New Roman';
const CONTENT_W = 9360; // DXA (6.5in)

// ---------- inline markup: **bold**, _italic_, `code` ----------
function runs(text, base = {}) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|(?<![A-Za-z0-9])_[^_]+_(?![A-Za-z0-9])|`[^`]+`)/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(new TextRun({ text: text.slice(last, m.index), ...base }));
    const t = m[0];
    if (t.startsWith('**')) out.push(new TextRun({ text: t.slice(2, -2), bold: true, ...base }));
    else if (t.startsWith('`')) out.push(new TextRun({ text: t.slice(1, -1), font: 'Consolas', size: 21, ...base }));
    else out.push(new TextRun({ text: t.slice(1, -1), italics: true, ...base }));
    last = m.index + t.length;
  }
  if (last < text.length) out.push(new TextRun({ text: text.slice(last), ...base }));
  return out;
}

let olInstance = 0;
let figNo = {}, tabNo = {};
let chapter = 0;

function pngSize(file) {
  const b = fs.readFileSync(file);
  return { w: b.readUInt32BE(16), h: b.readUInt32BE(20) };
}

const cellBorder = { style: BorderStyle.SINGLE, size: 4, color: '808080' };
const borders = { top: cellBorder, bottom: cellBorder, left: cellBorder, right: cellBorder };

function makeTable({ head, rows, widths, caption, small }) {
  const total = widths.reduce((a, b) => a + b, 0);
  const scale = CONTENT_W / total;
  const w = widths.map((x) => Math.floor(x * scale));
  w[w.length - 1] += CONTENT_W - w.reduce((a, b) => a + b, 0);
  const size = small ? 20 : 22;
  const mk = (txt, i, isHead) => new TableCell({
    borders, width: { size: w[i], type: WidthType.DXA },
    shading: isHead ? { fill: 'D9E2F3', type: ShadingType.CLEAR, color: 'auto' } : undefined,
    margins: { top: 60, bottom: 60, left: 100, right: 100 },
    children: String(txt).split('\n').map((line) => new Paragraph({
      spacing: { line: 260, after: 0 },
      children: runs(line, { font: FONT, size, bold: isHead || undefined }),
    })),
  });
  const out = [];
  if (caption) {
    tabNo[chapter] = (tabNo[chapter] || 0) + 1;
    out.push(new Paragraph({
      keepNext: true, spacing: { before: 200, after: 80 },
      children: [new TextRun({ text: `Table ${chapter}.${tabNo[chapter]}: `, bold: true, font: FONT, size: 22 }), ...runs(caption, { font: FONT, size: 22, italics: true })],
    }));
  }
  out.push(new Table({
    width: { size: CONTENT_W, type: WidthType.DXA }, columnWidths: w,
    rows: [
      new TableRow({ tableHeader: true, children: head.map((h, i) => mk(h, i, true)) }),
      ...rows.map((r) => new TableRow({ cantSplit: true, children: r.map((c, i) => mk(c, i, false)) })),
    ],
  }));
  out.push(new Paragraph({ spacing: { after: 120 }, children: [] }));
  return out;
}

function figure({ file, caption, width = 600 }) {
  const f = path.join(FIG, file);
  const { w, h } = pngSize(f);
  const height = Math.round(width * h / w);
  const maxH = 820; // keep on one page
  const [fw, fh] = height > maxH ? [Math.round(width * maxH / height), maxH] : [width, height];
  figNo[chapter] = (figNo[chapter] || 0) + 1;
  return [
    new Paragraph({ alignment: AlignmentType.CENTER, keepNext: true, spacing: { before: 200, after: 60 },
      children: [new ImageRun({ type: 'png', data: fs.readFileSync(f), transformation: { width: fw, height: fh },
        altText: { title: caption, description: caption, name: file } })] }),
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 },
      children: [new TextRun({ text: `Figure ${chapter}.${figNo[chapter]}: `, bold: true, font: FONT, size: 22 }), ...runs(caption, { font: FONT, size: 22, italics: true })] }),
  ];
}

function render(blocks) {
  const out = [];
  for (const [type, val] of blocks) {
    switch (type) {
      case 'h1':
        chapter += 1;
        out.push(new Paragraph({ heading: HeadingLevel.HEADING_1, pageBreakBefore: true, alignment: AlignmentType.CENTER, children: [new TextRun(val)] }));
        break;
      case 'h1x': // unnumbered section (references, appendices)
        out.push(new Paragraph({ heading: HeadingLevel.HEADING_1, pageBreakBefore: true, alignment: AlignmentType.CENTER, children: [new TextRun(val)] }));
        break;
      case 'h2': out.push(new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(val)] })); break;
      case 'h3': out.push(new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(val)] })); break;
      case 'p': out.push(new Paragraph({ alignment: AlignmentType.JUSTIFIED, children: runs(val) })); break;
      case 'ul':
        for (const item of val) out.push(new Paragraph({ alignment: AlignmentType.JUSTIFIED, numbering: { reference: 'bullets', level: 0 }, spacing: { after: 60 }, children: runs(item) }));
        out.push(new Paragraph({ spacing: { after: 60 }, children: [] }));
        break;
      case 'ol':
        olInstance += 1;
        for (const item of val) out.push(new Paragraph({ alignment: AlignmentType.JUSTIFIED, numbering: { reference: 'numbers', level: 0, instance: olInstance }, spacing: { after: 60 }, children: runs(item) }));
        out.push(new Paragraph({ spacing: { after: 60 }, children: [] }));
        break;
      case 'table': out.push(...makeTable(val)); break;
      case 'fig': out.push(...figure(val)); break;
      case 'code':
        for (const line of val.split('\n')) out.push(new Paragraph({
          spacing: { line: 240, after: 0 }, shading: { fill: 'F2F2F2', type: ShadingType.CLEAR, color: 'auto' },
          indent: { left: 200, right: 200 },
          children: [new TextRun({ text: line || ' ', font: 'Consolas', size: 18 })] }));
        out.push(new Paragraph({ spacing: { after: 120 }, children: [] }));
        break;
      case 'ref':
        out.push(new Paragraph({ alignment: AlignmentType.JUSTIFIED, indent: { left: 720, hanging: 720 }, spacing: { after: 120 }, children: runs(val) }));
        break;
      case 'center':
        out.push(new Paragraph({ alignment: AlignmentType.CENTER, children: runs(val) }));
        break;
      default: throw new Error('unknown block ' + type);
    }
  }
  return out;
}

const chapters = ['ch1', 'ch2', 'ch3', 'ch4', 'ch5', 'ch6', 'refs'].flatMap((n) => require(`./${n}.js`));

const doc = new Document({
  creator: 'PhishGuard project',
  title: 'Design and Implementation of a Phishing Detection System for Liberia Telecommunications Corporation',
  styles: {
    default: { document: { run: { font: FONT, size: 24 }, paragraph: { spacing: { line: 360, after: 120 } } } },
    paragraphStyles: [
      { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 28, bold: true, font: FONT, allCaps: true }, paragraph: { spacing: { before: 0, after: 360 }, outlineLevel: 0 } },
      { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 24, bold: true, font: FONT }, paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 1, keepNext: true } },
      { id: 'Heading3', name: 'Heading 3', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 24, bold: true, italics: true, font: FONT }, paragraph: { spacing: { before: 180, after: 100 }, outlineLevel: 2, keepNext: true } },
    ],
  },
  numbering: {
    config: [
      { reference: 'bullets', levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: 'numbers', levels: [{ level: 0, format: LevelFormat.DECIMAL, text: '%1.', alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    ],
  },
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 22 })] })] }) },
    children: [
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 }, children: [new TextRun({ text: 'TABLE OF CONTENTS', bold: true, size: 28, font: FONT })] }),
      new TableOfContents('Table of Contents', { hyperlink: true, headingStyleRange: '1-3' }),
      ...render(chapters),
    ],
  }],
});

const out = process.argv[2] || path.join(__dirname, 'report.docx');
Packer.toBuffer(doc).then((buf) => { fs.writeFileSync(out, buf); console.log('written', out, (buf.length / 1024).toFixed(0) + ' KB'); });
