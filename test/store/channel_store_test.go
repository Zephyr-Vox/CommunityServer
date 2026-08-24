package store_test

import (
	"context"
	"errors"
	"testing"

	"zephyr.vox/server/ce/internal/store"
)

func TestChannelStoreUpdatesCountsAndProtectsNonEmptyGroups(t *testing.T) {
	stores, _ := newTestEnv(t)
	ctx := context.Background()
	creator := mustCreateUser(t, stores, "creator")
	group, err := stores.Channels.CreateGroup(ctx, "Original", 1, "public")
	if err != nil {
		t.Fatal(err)
	}
	if count, err := stores.Channels.CountGroups(ctx); err != nil || count != 1 {
		t.Fatalf("group count = %d, err = %v", count, err)
	}
	secondGroup, err := stores.Channels.CreateGroup(ctx, "Second", 1, "public")
	if err != nil {
		t.Fatal(err)
	}
	groups, err := stores.Channels.ListGroups(ctx)
	if err != nil || len(groups) != 2 || groups[0].ID != group.ID || groups[1].ID != secondGroup.ID {
		t.Fatalf("group order = %+v, err = %v", groups, err)
	}
	group, err = stores.Channels.UpdateGroup(ctx, group.ID, "Renamed", 2, "private")
	if err != nil || group.Name != "Renamed" || group.Position != 2 || group.Visibility != "private" || group.Version != 2 {
		t.Fatalf("updated group = %+v, err = %v", group, err)
	}

	channel, err := stores.Channels.Create(ctx, store.ChannelInput{
		GroupID:    &group.ID,
		Name:       "Temporary Voice",
		Mode:       "voice",
		Temporary:  1,
		Visibility: "private",
		Capacity:   32,
		Position:   3,
		Pinned:     1,
		CreatedBy:  &creator.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if count, err := stores.Channels.Count(ctx); err != nil || count != 2 {
		t.Fatalf("channel count = %d, err = %v", count, err)
	}
	if count, err := stores.Channels.CountTemporary(ctx); err != nil || count != 1 {
		t.Fatalf("temporary count = %d, err = %v", count, err)
	}
	if count, err := stores.Channels.CountTemporaryForCreator(ctx, &creator.ID); err != nil || count != 1 {
		t.Fatalf("creator temporary count = %d, err = %v", count, err)
	}

	channel, err = stores.Channels.Update(ctx, channel.ID, store.ChannelUpdate{
		GroupID:    &group.ID,
		Name:       "Updated Voice",
		Visibility: "private",
		Capacity:   16,
		Position:   4,
		Pinned:     0,
	})
	if err != nil || channel.Name != "Updated Voice" || channel.Capacity != 16 || channel.Position != 4 || channel.Pinned != 0 || channel.Version != 2 {
		t.Fatalf("updated channel = %+v, err = %v", channel, err)
	}
	if err := stores.Channels.DeleteGroup(ctx, group.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("delete non-empty group = %v, want ErrConflict", err)
	}
	if err := stores.Channels.Delete(ctx, channel.ID); err != nil {
		t.Fatal(err)
	}
	if err := stores.Channels.DeleteGroup(ctx, group.ID); err != nil {
		t.Fatal(err)
	}
}
