/* Based on hostfs to a significant extent */
#include <asm/fcntl.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/init.h>
#include <linux/limits.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <user/fs.h>

#include <sqlite3.h>
#include "fs/fake-db.h"
#include "../fs/hostfs/hostfs.h" // just a quick way to get stat without typing too much

struct fakefs_super {
    struct fakefs_db db;
    int root_fd;
};

// free with __putname
static char *dentry_name(struct dentry *dentry) {
    /* I know this sucks, but __dentry_path isn't public for some reason */
    struct vfsmount fake_mnt = {};
    struct path root = {.dentry = dentry->d_sb->s_root, .mnt = &fake_mnt};
    struct path new_path = {.dentry = dentry, .mnt = &fake_mnt};
    char *name = __getname();
    if (name == NULL)
        return ERR_PTR(-ENOMEM);
    char *path = __d_path(&new_path, &root, name, PATH_MAX);
    if (IS_ERR(path))
        return path;
    BUG_ON(path[0] != '/');
    if (strcmp(path, "/") == 0)
        path[0] = '\0';
    memmove(name, path, strlen(path) + 1);
    return name;
}

/***** inode *****/

static int read_inode(struct inode *ino);

#define INODE_FD(ino) (*((uintptr_t *) &(ino)->i_private))

static struct dentry *fakefs_lookup(struct inode *ino, struct dentry *dentry, unsigned int flags) {
    struct fakefs_super *info = ino->i_sb->s_fs_info;
    struct inode *child = NULL;

    char *path = dentry_name(dentry);
    if (IS_ERR(path))
        return ERR_PTR(PTR_ERR(path));
    db_begin(&info->db);
    inode_t child_ino = path_get_inode(&info->db, path);
    db_commit(&info->db);
    __putname(path);
    if (child_ino == 0)
        goto out;

    int fd = host_openat(INODE_FD(ino), dentry->d_name.name, O_RDWR, 0);
    if (fd == -EISDIR)
        fd = host_openat(INODE_FD(ino), dentry->d_name.name, O_RDONLY, 0);
    if (fd < 0) {
        child = ERR_PTR(fd);
        goto out;
    }

    child = new_inode(ino->i_sb);
    if (child == NULL) {
        child = ERR_PTR(-ENOMEM);
        host_close(fd);
        goto out;
    }
    child->i_ino = child_ino;
    INODE_FD(child) = fd;
    int err = read_inode(child);
    if (err < 0) {
        iput(child);
        /* TODO: check whether iput manages to close the FD by calling evict_inode */
        child = ERR_PTR(err);
        goto out;
    }

out:
    if (IS_ERR(child))
        printk("fakefs_lookup failed: %pe\n", child);
    return d_splice_alias(child, dentry);
}

static int fakefs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl) {
    struct fakefs_super *info = dir->i_sb->s_fs_info;
    int fd = host_openat(INODE_FD(dir), dentry->d_name.name, O_CREAT | O_RDWR | (excl ? O_EXCL : 0), 0666);
    if (fd < 0)
        return fd;

    struct inode *child = new_inode(dir->i_sb);
    if (child == NULL) {
        host_close(fd);
        return -ENOMEM;
    }
    INODE_FD(child) = fd;
    inode_init_owner(child, dir, mode);

    char *path = dentry_name(dentry);
    if (IS_ERR(path)) {
        iput(child);
        return PTR_ERR(path);
    }
    db_begin(&info->db);
    struct ish_stat ishstat = {
        .mode = mode,
        .uid = i_uid_read(child),
        .gid = i_gid_read(child),
    };
    child->i_ino = path_create(&info->db, path, &ishstat);
    __putname(path);
    db_commit(&info->db);

    int err = read_inode(child);
    if (err < 0) {
        iput(child);
        return err;
    }
    d_instantiate(dentry, child);
    return 0;
}

static int fakefs_rename(struct inode *from_dir, struct dentry *from_dentry, struct inode *to_dir, struct dentry *to_dentry, unsigned flags) {
    if (flags != 0)
        return -EINVAL;
    struct fakefs_super *info = from_dir->i_sb->s_fs_info;

    char *from_path = dentry_name(from_dentry);
    if (from_path == NULL)
        return -ENOMEM;
    char *to_path = dentry_name(to_dentry);
    if (to_path == NULL) {
        __putname(from_path);
        return -ENOMEM;
    }

    db_begin(&info->db);
    path_rename(&info->db, from_path, to_path);
    __putname(from_path);
    __putname(to_path);

    int err = host_renameat(INODE_FD(from_dir), from_dentry->d_name.name,
                            INODE_FD(to_dir), to_dentry->d_name.name);
    if (err < 0) {
        db_rollback(&info->db);
        return err;
    }
    db_commit(&info->db);

    return 0;
}

static int fakefs_link(struct dentry *from, struct inode *ino, struct dentry *to) {
    struct fakefs_super *info = ino->i_sb->s_fs_info;

    char *from_path = dentry_name(from);
    if (from_path == NULL)
        return -ENOMEM;
    char *to_path = dentry_name(to);
    if (to_path == NULL) {
        __putname(from_path);
        return -ENOMEM;
    }

    db_begin(&info->db);
    path_link(&info->db, from_path, to_path);
    __putname(from_path);
    __putname(to_path);

    int err = host_linkat(INODE_FD(from->d_parent->d_inode), from->d_name.name,
                          INODE_FD(to->d_parent->d_inode), to->d_name.name);
    if (err < 0) {
        db_rollback(&info->db);
        return err;
    }
    db_commit(&info->db);

    return 0;
}

static int fakefs_unlink(struct inode *dir, struct dentry *dentry) {
    struct fakefs_super *info = dir->i_sb->s_fs_info;
    char *path = dentry_name(dentry);
    if (path == NULL)
        return -ENOMEM;

    db_begin(&info->db);
    path_unlink(&info->db, path);
    __putname(path);

    int err = host_unlinkat(INODE_FD(dir), dentry->d_name.name);
    if (err < 0) {
        db_rollback(&info->db);
        return err;
    }
    db_commit(&info->db);
    return 0;
}

static int path_create_for_child(struct fakefs_super *info, struct inode *dir, struct dentry *dentry, struct ish_stat *ishstat) {
    char *path = dentry_name(dentry);
    if (IS_ERR(path))
        return PTR_ERR(path);

    struct inode *fake = new_inode(dir->i_sb);
    if (fake == NULL)
        return -ENOMEM;
    INODE_FD(fake) = -1;
    inode_init_owner(fake, dir, ishstat->mode);
    ishstat->mode = fake->i_mode;
    ishstat->uid = i_uid_read(fake);
    ishstat->gid = i_gid_read(fake);
    iput(fake);

    db_begin(&info->db);
    path_create(&info->db, path, ishstat);
    __putname(path);
    return 0;
}

static int fakefs_symlink(struct inode *dir, struct dentry *dentry, const char *target) {
    struct fakefs_super *info = dir->i_sb->s_fs_info;
    struct ish_stat ishstat = {.mode = 0777 | S_IFLNK};
    int err = path_create_for_child(info, dir, dentry, &ishstat);
    if (err < 0)
        return err;

    int fd = host_openat(INODE_FD(dir), dentry->d_name.name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        db_rollback(&info->db);
        return fd;
    }
    ssize_t res = host_write(fd, target, strlen(target));
    host_close(fd);
    if (res < 0) {
        host_unlinkat(INODE_FD(dir), dentry->d_name.name);
        db_rollback(&info->db);
        return res;
    }
    db_commit(&info->db);

    return 0;
}

static const struct inode_operations fakefs_iops = {
    // TODO
    /* .setattr = fakefs_setattr, */
};

static const struct inode_operations fakefs_dir_iops = {
    .lookup = fakefs_lookup,
    .create = fakefs_create,
    .rename = fakefs_rename,
    .link = fakefs_link,
    .unlink = fakefs_unlink,
    .symlink = fakefs_symlink,
    /* .setattr = fakefs_setattr, */
};

static const struct inode_operations fakefs_link_iops = {
    .get_link = page_get_link,
};

/***** file *****/

#define FILE_DIR(file) ((file)->private_data)

static int fakefs_iterate(struct file *file, struct dir_context *ctx) {
    if (FILE_DIR(file) == NULL) {
        int err = host_dup_opendir(INODE_FD(file->f_inode), &FILE_DIR(file));
        if (err < 0)
            return err;
    }
    void *dir = FILE_DIR(file);
    int res;
    if (ctx->pos == 0)
        res = host_rewinddir(dir);
    else
        res = host_seekdir(dir, ctx->pos - 1);
    if (res < 0)
        return res;
    struct host_dirent ent;
    for (;;) {
        res = host_readdir(dir, &ent);
        if (res <= 0)
            break;
        ctx->pos = host_telldir(dir) + 1;
        // TODO fix inode numbers!!!!!
        ent.ino = 0;
        if (!dir_emit(ctx, ent.name, ent.name_len, ent.ino, ent.type))
            break;
    }
    return res;
}

static int fakefs_dir_release(struct inode *ino, struct file *file) {
    if (FILE_DIR(file) != NULL)
        return host_closedir(FILE_DIR(file));
    return 0;
}

static const struct file_operations fakefs_file_fops = {
    .llseek = generic_file_llseek,
    .splice_read = generic_file_splice_read,
    .read_iter = generic_file_read_iter,
    .write_iter = generic_file_write_iter,
    .mmap  = generic_file_mmap,
};

static const struct file_operations fakefs_dir_fops = {
    .iterate = fakefs_iterate,
    .release = fakefs_dir_release,
};

/***** address space *****/

static int fakefs_readpage(struct file *file, struct page *page) {
    struct inode *inode = file ? file->f_inode : page->mapping->host;
    char *buffer = kmap(page);
    ssize_t res = host_pread(INODE_FD(inode), buffer, PAGE_SIZE, page_offset(page));
    if (res < 0) {
        ClearPageUptodate(page);
        SetPageError(page);
        goto out;
    }
    memset(buffer + res, 0, PAGE_SIZE - res);

    res = 0;
    SetPageUptodate(page);

out:
    flush_dcache_page(page);
    kunmap(page);
    unlock_page(page);
    return res;
}

static int fakefs_write_begin(struct file *file, struct address_space *mapping,
                              loff_t pos, unsigned len, unsigned flags,
                              struct page **pagep, void **fsdata) {
    pgoff_t index = pos >> PAGE_SHIFT;
    *pagep = grab_cache_page_write_begin(mapping, index, flags);
    if (!*pagep)
        return -ENOMEM;
    return 0;
}

/* copied from fakefs, I don't really know what it does or how it works */
static int fakefs_write_end(struct file *file, struct address_space *mapping,
                            loff_t pos, unsigned len, unsigned copied,
                            struct page *page, void *fsdata) {
    struct inode *inode = mapping->host;
    void *buffer;
    unsigned from = pos & (PAGE_SIZE - 1);

    buffer = kmap(page);
    ssize_t res = host_pwrite(INODE_FD(file->f_inode), buffer + from, copied, pos);
    kunmap(page);
    if (res < 0)
        goto out;

    if (!PageUptodate(page) && res == PAGE_SIZE)
        SetPageUptodate(page);

    pos += res;
    if (pos > inode->i_size)
        inode->i_size = pos;

out:
    unlock_page(page);
    put_page(page);
    return res;
}

static const struct address_space_operations fakefs_aops = {
    .readpage = fakefs_readpage,
    .set_page_dirty = __set_page_dirty_nobuffers,
    .write_begin = fakefs_write_begin,
    .write_end = fakefs_write_end,
};

static int read_inode(struct inode *ino) {
    struct fakefs_super *info = ino->i_sb->s_fs_info;
    struct ish_stat ishstat;
    inode_read_stat(&info->db, ino->i_ino, &ishstat);
    ino->i_mode = ishstat.mode;
    i_uid_write(ino, ishstat.uid);
    i_gid_write(ino, ishstat.gid);

    struct hostfs_stat host_stat;
    int err = stat_file(NULL, &host_stat, INODE_FD(ino));
    if (err < 0)
        return err;
    set_nlink(ino, host_stat.nlink);
    ino->i_size = host_stat.size;
    ino->i_blocks = host_stat.blocks;
    ino->i_atime.tv_sec = host_stat.atime.tv_sec;
    ino->i_atime.tv_nsec = host_stat.atime.tv_nsec;
    ino->i_ctime.tv_sec = host_stat.ctime.tv_sec;
    ino->i_ctime.tv_nsec = host_stat.ctime.tv_nsec;
    ino->i_mtime.tv_sec = host_stat.mtime.tv_sec;
    ino->i_mtime.tv_nsec = host_stat.mtime.tv_nsec;

    switch (ino->i_mode & S_IFMT) {
    case S_IFREG:
        ino->i_op = &fakefs_iops;
        ino->i_fop = &fakefs_file_fops;
        ino->i_mapping->a_ops = &fakefs_aops;
        break;
    case S_IFDIR:
        ino->i_op = &fakefs_dir_iops;
        ino->i_fop = &fakefs_dir_fops;
        break;
    case S_IFLNK:
        ino->i_op = &fakefs_link_iops;
        ino->i_mapping->a_ops = &fakefs_aops;
        inode_nohighmem(ino);
        break;
    case S_IFCHR:
    case S_IFBLK:
    case S_IFIFO:
    case S_IFSOCK:
        init_special_inode(ino, ino->i_mode & S_IFMT, ishstat.rdev);
        ino->i_op = &fakefs_iops;
        break;
    default:
        return -EIO;
    }
    return 0;
}

/***** superblock *****/

static void fakefs_evict_inode(struct inode *ino) {
    struct fakefs_super *info = ino->i_sb->s_fs_info;
    if (INODE_FD(ino) != info->root_fd && INODE_FD(ino) != -1)
        host_close(INODE_FD(ino));
    INODE_FD(ino) = 0;
    truncate_inode_pages_final(&ino->i_data);
    clear_inode(ino);
}

static const struct super_operations fakefs_super_ops = {
    .evict_inode = fakefs_evict_inode,
};

static int fakefs_fill_super(struct super_block *sb, struct fs_context *fc) {
    struct fakefs_super *info = sb->s_fs_info;

    struct inode *root = new_inode(sb);
    if (root == NULL)
        return -ENOMEM;
    root->i_ino = path_get_inode(&info->db, "");
    if (root->i_ino == 0) {
        printk("fakefs: could not find root inode\n");
        iput(root);
        return -EINVAL;
    }
    INODE_FD(root) = info->root_fd;
    int err = read_inode(root);
    if (err < 0) {
        iput(root);
        return err;
    }

    sb->s_op = &fakefs_super_ops;
    sb->s_root = d_make_root(root);
    if (sb->s_root == NULL) {
        iput(root);
        return -ENOMEM;
    }

    return 0;
}

/***** context/init *****/

struct fakefs_context {
    const char *path;
};

static int fakefs_fc_parse_monolithic(struct fs_context *fc, void *data) {
    const char *str = data;
    struct fakefs_context *ctx = fc->fs_private;
    ctx->path = kstrdup(str, GFP_KERNEL);
    if (ctx->path == NULL)
        return -ENOMEM;
    return 0;
}

static void fakefs_fc_free(struct fs_context *fc) {
    struct fakefs_context *ctx = fc->fs_private;
    kfree(ctx->path);
    kfree(ctx);
}

static int fakefs_get_tree(struct fs_context *fc) {
    fc->s_fs_info = kzalloc(sizeof(struct fakefs_super), GFP_KERNEL);
    if (fc->s_fs_info == NULL)
        return -ENOMEM;
    struct fakefs_super *info = fc->s_fs_info;
    struct fakefs_context *ctx = fc->fs_private;

    char *path = kmalloc(strlen(ctx->path) + 10, GFP_KERNEL);
    strcpy(path, ctx->path);
    strcat(path, "/data");
    info->root_fd = host_open(path, O_RDONLY);
    if (info->root_fd < 0) {
        kfree(path);
        return info->root_fd;
    }

    strcpy(path, ctx->path);
    strcat(path, "/meta.db");
    int err = fake_db_init(&info->db, path, info->root_fd);
    if (err < 0) {
        kfree(path);
        return err;
    }
    kfree(path);

    err = vfs_get_super(fc, vfs_get_keyed_super, fakefs_fill_super);
    if (err < 0)
        return err;
    return 0;
}

static struct fs_context_operations fakefs_context_ops = {
    .parse_monolithic = fakefs_fc_parse_monolithic,
    .free = fakefs_fc_free,
    .get_tree = fakefs_get_tree,
};

static int fakefs_init_fs_context(struct fs_context *fc) {
    fc->ops = &fakefs_context_ops;
    fc->fs_private = kzalloc(sizeof(struct fakefs_context), GFP_KERNEL);
    if (fc->fs_private == NULL)
        return -ENOMEM;
    return 0;
}

static void fakefs_kill_sb(struct super_block *sb) {
    struct fakefs_super *info = sb->s_fs_info;
    fake_db_deinit(&info->db);
    host_close(info->root_fd);
    kill_anon_super(sb);
    kfree(info);
}

static struct file_system_type fakefs_type = {
    .name = "fakefs",
    .init_fs_context = fakefs_init_fs_context,
    .kill_sb = fakefs_kill_sb,
};

static int fakefs_init(void) {
    return register_filesystem(&fakefs_type);
}

__initcall(fakefs_init);
