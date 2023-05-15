# Follow the steps here to create a service account for bots
# https://docs.gspread.org/en/latest/oauth2.html
# You'll need to download OAuth client ID to a JSON file somewhere
# Once you have all that, share the spreadsheet with the email address listed in the JSON file
# under the key "client_email"
# You client should be ready to rock'n'roll
#

import pandas
import gspread
from string import ascii_uppercase


class Client():
    def __init__(self, credentials: str, spreadsheet: str = None):
        """This is a helper library for uploading data to Google spreadsheets

        Args:
            credentials (str): A path to the credentials JSON file downloaded from Google Cloud Console
            spreadsheet (str, optional): A spreadsheet to open. Defaults to None.
        """
        self.handle = gspread.service_account(filename=credentials)
        if spreadsheet is not None and len(spreadsheet) > 0:
            self.spreadsheet = self.get_spreadsheet(spreadsheet)
    
    def get_column_name(self, column_index: int) -> str:
        """Convert a column index into a Worksheet column name

        Args:
            column_index (int): The index of this column

        Returns:
            str: The name for this column in a Worksheet
        """
        if column_index < len(ascii_uppercase):
            return ascii_uppercase[column_index]
        else:
            return self.get_column_name(column_index=(column_index//len(ascii_uppercase))-1) + ascii_uppercase[column_index%len(ascii_uppercase)]
    
    def format_range(self, row_start: int, row_len: int, col_start: int, col_len: int) -> str:
        """Create a range for a given table

        Args:
            row_start (int): The index of the first row
            row_len (int): The length of each row
            col_start (int): The index of the first column
            col_len (int): The length of each column

        Returns:
            str: The range for the given table
        """
        start = self.get_column_name(column_index=col_start) + f"{row_start}"
        end = self.get_column_name(column_index=col_start+col_len) + f"{row_start+row_len}"
        return f"{start}:{end}"
    
    def get_spreadsheet(self, spreadsheet: str) -> gspread.Spreadsheet:
        """Open a specific spreadsheet

        Args:
            spreadsheet (str): The name of the spreadsheet

        Returns:
            gspread.Spreadsheet: A Spreadsheet object
        """
        try:
            obj = self.handle.open(spreadsheet)
            return obj
        except gspread.SpreadsheetNotFound:
            return None
    
    def get_worksheet(self, spreadsheet: gspread.Spreadsheet, name: str=None, index: int=None) -> gspread.Worksheet:
        """Open a specific worksheet in a spreadsheet

        Args:
            spreadsheet (gspread.Spreadsheet): The spreadsheet object that contains the worksheet
            name (str, optional): The name of the worksheet. Defaults to None.
            index (int, optional): The index of the worksheet. Defaults to None.

        Raises:
            Exception: name and index cannot be None at the same time

        Returns:
            gspread.worksheet.Worksheet: A Workshet object

        """
        if name is None and index is None:
            raise Exception("Name and index cannot both be none")
        
        if name is not None:
            try:
                obj = spreadsheet.worksheet(name)
                return obj
            except gspread.WorksheetNotFound:
                return None
            except:
                return None
        elif index is not None:
            try:
                obj = spreadsheet.get_worksheet(index=index)
                return obj
            except gspread.WorksheetNotFound:
                return None
            except:
                return None
    
    def new_worksheet(self, spreadsheet: gspread.Spreadsheet, name: str, rows: int, cols: int, index: int=None) -> gspread.Worksheet:
        """Create a new worksheet

        Args:
            spreadsheet (gspread.Spreadsheet): The spreadsheet to use
            name (str): The name of the worksheet
            rows (int): The number of rows in the worksheet
            cols (int): The number of rows in the worksheet
            index (int, optional): The index of this worksheet. Defaults to None.

        Returns:
            gspread.worksheet.Worksheet: The newly created worksheet object
        """
        try:
            obj = spreadsheet.add_worksheet(title=name, rows=rows, cols=cols, index=index)
            return obj
        except:
            return None
        

    def insert_dataframe(self, worksheet: gspread.Worksheet, df: pandas.DataFrame, start_row: int=None, start_col: int=None, range_str: str=None):
        """Insert a pandas DataFrame into a worksheet

        Args:
            worksheet (gspread.Worksheet): The worksheet object
            df (pandas.DataFrame): The dataframe to insert
            start_row (int, optional): A row index to start inserting. Defaults to None.
            start_col (int, optional): A column index to start inserting. Defaults to None.
            range_str (str, optional): A range to use for inserting. Defaults to None.
        """
        if start_row is not None and start_col is not None:
            range_str = self.format_range(row_start=start_row, row_len=len(df), col_start=start_col, col_len=len(df.columns))
            worksheet.update(range_name=range_str, values=[df.columns.values.tolist()] + df.values.tolist())
        elif range_str is not None:
            worksheet.update(range_name=range_str, values=[df.columns.values.tolist()] + df.values.tolist())
        else:
            worksheet.update([df.columns.values.tolist()] + df.values.tolist())
    
    def append_list(self, worksheet: gspread.Worksheet, data: list, start_row: int=None, start_col: int=None, range_str: str=None):
        """Append a list to the worksheet

        Args:
            worksheet (gspread.Worksheet): The worksheet to use
            data (list): The data to be inserted
            start_row (int, optional): A row index to use for appending. Defaults to None.
            start_col (int, optional): A column index to use for appending. Defaults to None.
            range_str (str, optional): A range to use for appending. Defaults to None.

        Raises:
            Exception: The data should only contain primitive types such as int, float or str
        """
        for item in data:
            if isinstance(item, int) or isinstance(item, str) or isinstance(item, float):
                pass
            else:
                raise Exception("The list can only contain int,str or float objects")
        
        if start_row is not None and start_col is not None:
            range_str = self.format_range(row_start=start_row, row_len=1, col_start=start_col, col_len=len(data))
            worksheet.append_row(values=data, table_range=range_str)
        elif start_row is not None:
            range_str = self.format_range(row_start=start_row, row_len=0, col_start=0, col_len=len(data))
            worksheet.append_row(values=data, table_range=range_str)
        elif start_col is not None:
            range_str = self.format_range(row_start=0, row_len=0, col_start=start_col, col_len=len(data))
            worksheet.append_row(values=data, table_range=range_str)
        elif range_str is not None:
            worksheet.append_row(values=data, table_range=range_str)
        else:
            worksheet.append_row(values=data)
    
    def make_bold(self, worksheet: gspread.Worksheet, row: int=None, col: int=None, range_str: str=None):
        """Make a set of cells bold in the worksheet

        Args:
            worksheet (gspread.Worksheet): The worksheet to use
            row (int, optional): The row index to use. Defaults to None.
            col (int, optional): The column index to use. Defaults to None.
            range_str (str, optional): A range to use. Defaults to None.

        Raises:
            Exception: At least one option out of row, col or range_str should be provided
        """
        if row is not None:
            range_str = self.format_range(row_start=row, row_len=0, col_start=0, col_len=worksheet.col_count)
            worksheet.format(ranges=range_str, format={"textFormat": {"bold": True}})
        elif col is not None:
            range_str = self.format_range(row_start=0, row_len=worksheet.row_count, col_start=col, col_len=0)
            worksheet.format(ranges=range_str, format={"textFormat": {"bold": True}})
        elif range_str is not None:
            worksheet.format(ranges=range_str, format={"textFormat": {"bold": True}})
        else:
            raise Exception("Either of row, column or range should be provided")
