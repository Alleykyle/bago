from django.core.management.base import BaseCommand
from django.conf import settings
from app.models import Employee, UserProfile
from django.contrib.auth.models import User
import os
import shutil
from datetime import datetime
import sqlite3

class Command(BaseCommand):
    help = 'Database utilities for backup, info, and statistics'
    
    def add_arguments(self, parser):
        parser.add_argument('--info', action='store_true', help='Show database info')
        parser.add_argument('--backup', action='store_true', help='Backup database')
        parser.add_argument('--stats', action='store_true', help='Show database statistics')
        parser.add_argument('--size', action='store_true', help='Show database size')
        parser.add_argument('--tables', action='store_true', help='List all tables')
    
    def handle(self, *args, **options):
        if options['info']:
            self.show_db_info()
        elif options['backup']:
            self.backup_database()
        elif options['stats']:
            self.show_stats()
        elif options['size']:
            self.show_db_size()
        elif options['tables']:
            self.show_tables()
        else:
            self.stdout.write(self.style.WARNING('Available options:'))
            self.stdout.write('  --info     Show database configuration')
            self.stdout.write('  --backup   Backup database file')
            self.stdout.write('  --stats    Show data statistics')
            self.stdout.write('  --size     Show database file size')
            self.stdout.write('  --tables   List all database tables')
    
    def show_db_info(self):
        db_config = settings.DATABASES['default']
        self.stdout.write(self.style.SUCCESS('=== DATABASE INFO ==='))
        self.stdout.write(f"Engine: {db_config['ENGINE']}")
        self.stdout.write(f"Name: {db_config['NAME']}")
        if 'HOST' in db_config and db_config['HOST']:
            self.stdout.write(f"Host: {db_config['HOST']}")
        if 'PORT' in db_config and db_config['PORT']:
            self.stdout.write(f"Port: {db_config['PORT']}")
        
        # Check if database file exists
        db_path = db_config['NAME']
        if os.path.exists(db_path):
            self.stdout.write(self.style.SUCCESS('✓ Database file exists'))
            # Get file size
            size = os.path.getsize(db_path)
            self.stdout.write(f"Size: {self.format_bytes(size)}")
        else:
            self.stdout.write(self.style.ERROR('✗ Database file not found'))
    
    def backup_database(self):
        db_path = settings.DATABASES['default']['NAME']
        
        if not os.path.exists(db_path):
            self.stdout.write(self.style.ERROR('Database file not found!'))
            return
        
        # Create backups directory if it doesn't exist
        backup_dir = 'backups'
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"{backup_dir}/db_backup_{timestamp}.sqlite3"
        
        try:
            shutil.copy2(db_path, backup_name)
            backup_size = os.path.getsize(backup_name)
            self.stdout.write(self.style.SUCCESS(f'✓ Database backed up successfully!'))
            self.stdout.write(f'Backup file: {backup_name}')
            self.stdout.write(f'Backup size: {self.format_bytes(backup_size)}')
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Backup failed: {str(e)}'))
    
    def show_stats(self):
        self.stdout.write(self.style.SUCCESS('=== DATABASE STATISTICS ==='))
        
        try:
            # Employee statistics
            total_employees = Employee.objects.count()
            self.stdout.write(f"Total Employees: {total_employees}")
            
            if total_employees > 0:
                # Group by task
                tasks = Employee.objects.values_list('task', flat=True).distinct()
                self.stdout.write("\nEmployees by Task:")
                for task in tasks:
                    count = Employee.objects.filter(task=task).count()
                    self.stdout.write(f"  {task}: {count}")
            
            # User statistics
            total_users = User.objects.count()
            active_users = User.objects.filter(is_active=True).count()
            self.stdout.write(f"\nTotal Users: {total_users}")
            self.stdout.write(f"Active Users: {active_users}")
            
            # UserProfile statistics
            profiles = UserProfile.objects.count()
            self.stdout.write(f"User Profiles: {profiles}")
            
            if profiles > 0:
                roles = UserProfile.objects.values_list('role', flat=True).distinct()
                self.stdout.write("\nUsers by Role:")
                for role in roles:
                    count = UserProfile.objects.filter(role=role).count()
                    self.stdout.write(f"  {role or 'No Role'}: {count}")
                    
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error getting statistics: {str(e)}'))
    
    def show_db_size(self):
        db_path = settings.DATABASES['default']['NAME']
        
        if os.path.exists(db_path):
            size = os.path.getsize(db_path)
            self.stdout.write(f"Database size: {self.format_bytes(size)}")
            
            # Show backup sizes if they exist
            backup_dir = 'backups'
            if os.path.exists(backup_dir):
                backups = [f for f in os.listdir(backup_dir) if f.endswith('.sqlite3')]
                if backups:
                    self.stdout.write(f"\nBackup files ({len(backups)}):")
                    for backup in sorted(backups):
                        backup_path = os.path.join(backup_dir, backup)
                        backup_size = os.path.getsize(backup_path)
                        self.stdout.write(f"  {backup}: {self.format_bytes(backup_size)}")
        else:
            self.stdout.write(self.style.ERROR('Database file not found!'))
    
    def show_tables(self):
        db_path = settings.DATABASES['default']['NAME']
        
        if not os.path.exists(db_path):
            self.stdout.write(self.style.ERROR('Database file not found!'))
            return
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get all table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            self.stdout.write(self.style.SUCCESS('=== DATABASE TABLES ==='))
            for table in tables:
                table_name = table[0]
                cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
                count = cursor.fetchone()[0]
                self.stdout.write(f"{table_name}: {count} records")
            
            conn.close()
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error reading tables: {str(e)}'))
    
    def format_bytes(self, bytes):
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024.0:
                return f"{bytes:.1f} {unit}"
            bytes /= 1024.0
        return f"{bytes:.1f} TB"