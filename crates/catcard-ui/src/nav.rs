//! Where the person is in the menus: the way back, one level at a time.
//!
//! Every menu used to name its parent. That is one answer per screen, and a screen
//! reachable from two places -- Notes is a main-menu tile, a Settings row and a Debug
//! row -- can only be right about one of them: open it from the main menu and back put
//! you in Settings. Going back also always landed on the first row, so a person three
//! rows down a long list started over from the top each time they looked at something.
//!
//! So the run loop keeps the way it came instead. Opening a screen pushes the one it was
//! opened from, with the row that was selected; going back pops it and puts the cursor on
//! that row again. The stack is small and fixed -- a [`Place`] is a screen id and a `u8`
//! -- and it never refuses: a push past its depth drops the *oldest* level, because the
//! levels nearest the person are the ones back walks through first, and a menu tree
//! deeper than the stack is a menu tree nobody walks all the way up anyway.
//!
//! The screen type is the caller's. This module knows nothing about which screens exist,
//! so it can be tested on the host.

/// One level: the screen, and the row its cursor was on.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Place<S> {
    pub screen: S,
    /// The selected row, as the list numbers its items. A `u8` because a menu is a list a
    /// person scrolls through by hand; one longer than 255 rows saturates here and is
    /// clamped to its last row when restored.
    cursor: u8,
}

impl<S: Copy> Place<S> {
    /// The row to put the cursor back on, for a list that is now `len` long.
    ///
    /// **Clamped, never trusted.** The list may have changed under the remembered row
    /// while it was out of sight -- a setting that hides a row, a wallet that reorders
    /// the main menu -- and a cursor past the end selects nothing, which is a screen that
    /// ignores its OK key.
    pub fn cursor(&self, len: usize) -> usize {
        clamp(self.cursor as usize, len)
    }
}

/// A cursor, clamped into a list of `len` rows. Zero for an empty list.
pub fn clamp(cursor: usize, len: usize) -> usize {
    cursor.min(len.saturating_sub(1))
}

/// The levels above the current screen, nearest last.
pub struct NavStack<S, const N: usize> {
    places: [Place<S>; N],
    len: u8,
}

impl<S: Copy, const N: usize> NavStack<S, N> {
    /// Empty. `fill` is only what the unused slots hold; it is never handed back.
    pub const fn new(fill: S) -> Self {
        const {
            assert!(N > 0 && N <= u8::MAX as usize, "a stack of 1..=255 levels");
        }
        Self {
            places: [Place {
                screen: fill,
                cursor: 0,
            }; N],
            len: 0,
        }
    }

    /// Going deeper: remember `screen`, with the cursor on `cursor`.
    ///
    /// Full, the oldest level is dropped to make room. Never a panic and never a refusal:
    /// the person has already pressed the key, and a stack that said no would leave them
    /// on a screen with no way back at all.
    pub fn push(&mut self, screen: S, cursor: usize) {
        let place = Place {
            screen,
            cursor: u8::try_from(cursor).unwrap_or(u8::MAX),
        };
        let len = self.len as usize;
        if len == N {
            self.places.copy_within(1.., 0);
            self.places[N - 1] = place;
        } else {
            self.places[len] = place;
            self.len += 1;
        }
    }

    /// Going back: the level the current screen was opened from, if there is one.
    pub fn pop(&mut self) -> Option<Place<S>> {
        let len = self.len.checked_sub(1)?;
        self.len = len;
        Some(self.places[len as usize])
    }

    /// Forget every level: the person has been put somewhere the way back no longer
    /// leads from (the main menu of a wallet that did not exist a moment ago).
    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    enum S {
        Main,
        Settings,
        Login,
        Utils,
    }

    #[test]
    fn back_retraces_the_way_in_with_each_row() {
        // Settings -> Login -> Trick PINs: back, back lands on Settings, on Login's row.
        let mut nav: NavStack<S, 8> = NavStack::new(S::Main);
        nav.push(S::Main, 4);
        nav.push(S::Settings, 2);
        let p = nav.pop().unwrap();
        assert_eq!((p.screen, p.cursor(20)), (S::Settings, 2));
        let p = nav.pop().unwrap();
        assert_eq!((p.screen, p.cursor(6)), (S::Main, 4));
        assert!(nav.is_empty());
    }

    #[test]
    fn back_from_the_top_is_nothing() {
        let mut nav: NavStack<S, 4> = NavStack::new(S::Main);
        assert_eq!(nav.pop(), None);
        nav.push(S::Utils, 1);
        nav.pop();
        assert_eq!(nav.pop(), None);
        assert_eq!(nav.len(), 0);
    }

    #[test]
    fn the_same_screen_from_two_places_goes_back_to_each() {
        // Notes from the main menu, then Notes from Settings: each back is its own opener.
        let mut nav: NavStack<S, 8> = NavStack::new(S::Main);
        nav.push(S::Main, 2);
        assert_eq!(nav.pop().unwrap().screen, S::Main);
        nav.push(S::Main, 3);
        nav.push(S::Settings, 7);
        assert_eq!(nav.pop().unwrap().screen, S::Settings);
    }

    #[test]
    fn overflow_drops_the_oldest_level_and_keeps_the_nearest() {
        let mut nav: NavStack<S, 3> = NavStack::new(S::Main);
        nav.push(S::Main, 0);
        nav.push(S::Settings, 1);
        nav.push(S::Login, 2);
        nav.push(S::Utils, 3);
        assert_eq!(nav.len(), 3);
        let order: [(S, usize); 3] = core::array::from_fn(|_| {
            let p = nav.pop().unwrap();
            (p.screen, p.cursor(10))
        });
        assert_eq!(order, [(S::Utils, 3), (S::Login, 2), (S::Settings, 1)]);
        assert_eq!(nav.pop(), None, "the oldest level is the one that went");
    }

    #[test]
    fn a_long_walk_never_panics() {
        let mut nav: NavStack<S, 8> = NavStack::new(S::Main);
        for i in 0..1000 {
            nav.push(S::Settings, i);
        }
        assert_eq!(nav.len(), 8);
        while nav.pop().is_some() {}
    }

    #[test]
    fn a_remembered_row_past_the_end_is_clamped() {
        // The main menu lost a row (a setting hid it) while the person was in Settings.
        let mut nav: NavStack<S, 8> = NavStack::new(S::Main);
        nav.push(S::Main, 6);
        let p = nav.pop().unwrap();
        assert_eq!(p.cursor(5), 4);
        assert_eq!(p.cursor(7), 6);
        assert_eq!(p.cursor(0), 0, "an empty list has only row zero");
    }

    #[test]
    fn a_cursor_too_big_to_store_saturates_and_is_clamped() {
        let mut nav: NavStack<S, 2> = NavStack::new(S::Main);
        nav.push(S::Utils, 1000);
        assert_eq!(nav.pop().unwrap().cursor(usize::MAX), 255);
        nav.push(S::Utils, 1000);
        assert_eq!(nav.pop().unwrap().cursor(40), 39);
    }

    #[test]
    fn clear_forgets_everything() {
        let mut nav: NavStack<S, 8> = NavStack::new(S::Main);
        nav.push(S::Main, 1);
        nav.push(S::Settings, 2);
        nav.clear();
        assert!(nav.is_empty());
        assert_eq!(nav.pop(), None);
    }

    #[test]
    fn clamp_is_a_row_of_the_list() {
        assert_eq!(clamp(0, 0), 0);
        assert_eq!(clamp(3, 4), 3);
        assert_eq!(clamp(4, 4), 3);
    }
}
