package com.innoc.secureline.contacts;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.support.v4.content.CursorLoader;

import com.innoc.secureline.directory.NumberFilter;
import com.innoc.secureline.util.FilteredCursorFactory;

import java.util.HashSet;
import java.util.Set;

public class RegisteredUserCursorLoader extends CursorLoader {

  private final Uri      uri;
  private final String[] projection;
  private final String   selection;
  private final String   order;

  private final String  numberColumn;
  private final boolean unique;

  public RegisteredUserCursorLoader(Context context, Uri uri, String[] projection,
                                    String selection, String order, String numberColumn,
                                    boolean unique)
  {
    super(context);

    this.uri          = uri;
    this.projection   = projection;
    this.selection    = selection;
    this.order        = order;
    this.numberColumn = numberColumn;
    this.unique       = unique;
  }

  @Override
  public Cursor loadInBackground() {
    final NumberFilter numberFilter = NumberFilter.deserializeFromFile(getContext());
    final Cursor       cursor       = getContext().getContentResolver().query(uri, projection,
                                                                              selection, null, order);

    final int numberColumnIndex = cursor.getColumnIndexOrThrow(numberColumn);

    return FilteredCursorFactory.getFilteredCursor(cursor, new FilteredCursorFactory.CursorFilter() {
        private final Set<String> uniqueNumbers = new HashSet<String>();

        @Override
        public boolean isIncluded(Cursor cursor) {
            String number = cursor.getString(numberColumnIndex);

            if (!uniqueNumbers.contains(number) && numberFilter.containsNumber(getContext(), number)) {
                if (unique) uniqueNumbers.add(number);
                return true;
            }

            return false;
        }
    });
  }

  @Override
  public void onReset() {
    super.onReset();
  }
}
