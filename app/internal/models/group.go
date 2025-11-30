// Package models defines data structures for CheckTheBox application.
// This file contains Group and UserGroup models for organizational management.
package models

import "time"

// Group represents an organizational unit or department.
// Used for bulk policy assignments and organizational hierarchy.
//
// Related: FR-011 (Group/Department Management)
// Database: groups table
type Group struct {
	ID          int       `db:"id"`          // Primary key, auto-increment
	Name        string    `db:"name"`        // Unique group name (e.g., "Engineering", "Sales")
	Description string    `db:"description"` // Optional description of group purpose
	CreatedAt   time.Time `db:"created_at"`  // Timestamp when group was created
}

// UserGroup represents membership of a user in a group.
// Many-to-many relationship between users and groups.
//
// Related: FR-011 (Group/Department Management)
// Database: user_groups table with composite primary key
type UserGroup struct {
	UserID    int       `db:"user_id"`    // Foreign key to users table
	GroupID   int       `db:"group_id"`   // Foreign key to groups table
	CreatedAt time.Time `db:"created_at"` // Timestamp when user was added to group
}

// GroupWithMembers extends Group with member count for display purposes.
// Used in list views to show how many users are in each group.
type GroupWithMembers struct {
	Group
	MemberCount int `db:"member_count"` // Count of users assigned to this group
}
