"""Read the monthly targets workbook with Python's standard library."""
import io
import posixpath
import re
import xml.etree.ElementTree as ET
import zipfile
from decimal import Decimal, InvalidOperation

NS = {'x': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
      'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
      'p': 'http://schemas.openxmlformats.org/package/2006/relationships'}
MONTHS = ('JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC')


class WorkbookError(ValueError):
    pass


def read_xml(archive, path):
    info = archive.getinfo(path)
    if info.file_size > 2_000_000:
        raise WorkbookError('Workbook sheet is too large.')
    return ET.fromstring(archive.read(path))


def cell_value(cell, shared):
    kind = cell.get('t')
    if kind == 'inlineStr':
        return ''.join((e.text or '') for e in cell.findall('.//x:t', NS))
    v = cell.find('x:v', NS)
    if v is None:
        return None
    if kind == 's':
        return shared[int(v.text)]
    if kind in ('str', 'e'):
        return v.text
    try:
        return Decimal(v.text)
    except (InvalidOperation, TypeError):
        return v.text


def number(value, row, field):
    if value in (None, ''):
        return Decimal(0)
    try:
        n = Decimal(str(value))
        if not n.is_finite() or n < 0 or n > 1_000_000:
            raise InvalidOperation()
        return n
    except (InvalidOperation, ValueError):
        raise WorkbookError(f'Row {row}: invalid {field} target.')


def parse(data, month):
    if len(data) > 2_000_000:
        raise WorkbookError('Target file exceeds the 2 MB limit.')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if sum(i.file_size for i in archive.infolist()) > 8_000_000:
                raise WorkbookError('Workbook expands beyond the size limit.')
            workbook = read_xml(archive, 'xl/workbook.xml')
            rels = read_xml(archive, 'xl/_rels/workbook.xml.rels')
            relation = {r.get('Id'):r.get('Target') for r in rels}
            sheets = [(s.get('name'),relation.get(s.get('{'+NS['r']+'}id')))
                      for s in workbook.findall('x:sheets/x:sheet',NS)]
            wanted = MONTHS[int(month[5:7])-1]
            choices = [(name,target) for name,target in sheets if
                       name.upper() in (wanted, month, wanted+month[:4])]
            if len(choices)!=1:
                if len(sheets)==1:
                    choices=sheets
                else:
                    raise WorkbookError(f'Choose a workbook with one sheet named {wanted} for {month}.')
            name,target=choices[0]
            if not target:
                raise WorkbookError('Workbook sheet relationship is missing.')
            target=posixpath.normpath(posixpath.join('xl',target.lstrip('/'))) if not target.startswith('/') else target.lstrip('/')
            if not target.startswith('xl/worksheets/'):
                raise WorkbookError('Invalid worksheet location.')
            shared=[]
            if 'xl/sharedStrings.xml' in archive.namelist():
                root=read_xml(archive,'xl/sharedStrings.xml')
                shared=[''.join((t.text or '') for t in si.findall('.//x:t',NS))
                        for si in root.findall('x:si',NS)]
            root=read_xml(archive,target)
            rows=[]
            for r in root.findall('x:sheetData/x:row',NS):
                values={}
                for c in r.findall('x:c',NS):
                    letters=re.match(r'[A-Z]+',c.get('r',''))
                    if not letters: continue
                    col=0
                    for letter in letters.group(): col=col*26+ord(letter)-64
                    values[col]=cell_value(c,shared)
                rows.append((int(r.get('r','0')),values))
    except (zipfile.BadZipFile,KeyError,ET.ParseError,IndexError,TypeError) as error:
        raise WorkbookError('Invalid or unsupported XLSX file.') from error

    required={'TABS','POST','BB','BH','EXPATS'}
    headers=None
    for _,values in rows[:20]:
        labels={str(v).strip().upper():k for k,v in values.items() if v is not None}
        if required<=set(labels):
            headers=labels
            break
    if headers is None:
        raise WorkbookError('Missing TABS, POST, BB, BH, or Expats columns.')
    header_row=next(n for n,values in rows if str(values.get(headers['TABS'],'')).strip().upper()=='TABS')
    parsed=[]
    seen=set()
    for rownum,values in rows:
        if rownum<=header_row: continue
        raw=values.get(headers['TABS'])
        if raw is None or str(raw).strip()=='': continue
        username=str(raw).strip().upper()
        if not re.fullmatch(r'[A-Z0-9_-]{3,24}',username):
            raise WorkbookError(f'Row {rownum}: invalid TABS ID.')
        if username in seen:
            raise WorkbookError(f'Employee {username} appears more than once.')
        seen.add(username)
        post=number(values.get(headers['POST']),rownum,'POST')
        bb=number(values.get(headers['BB']),rownum,'BB')
        bh=number(values.get(headers['BH']),rownum,'BH')
        expats=number(values.get(headers['EXPATS']),rownum,'Expats')
        insurance=number(values.get(headers['INSURANCE']),rownum,'Insurance') if 'INSURANCE' in headers else Decimal(0)
        # An insurance-only employee is outside the currently tracked segments.
        if insurance > 0 and post == bb == bh == expats == 0:
            continue
        if len(parsed)>=300:
            raise WorkbookError('Maximum 300 employees per target workbook.')
        parsed.append({'username':username,'targets':{
            'POST':float(round(post, 2)),'BB':float(round(bb, 2)),
            'MUL':float(round(bh+expats, 2))}})
    if not parsed:
        raise WorkbookError('No employee targets found in the selected sheet.')
    return name,parsed
