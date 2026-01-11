import copy

import requests
from src.db.mysql_connect import ConMySql, stuf
from typing import List, Dict, Optional, Any
from collections import defaultdict
from datetime import datetime
from src import utils

logger = utils.Logger(__name__)


class CWEDataAPI:
    """
    CWE 数据管理类：
    优先查询数据库中数据，如果数据库中没有对应数据，则
    调用官方REST API、解析全量数据、使用dataset库存储到MySQL
    """

    def __init__(self):
        self.CWE_API_ROOT = "https://cwe-api.mitre.org/api/v1"
        self.TIMEOUT = 15
        self.db = ConMySql()

    def _parse_date(self, date_str: Optional[str]) -> Optional[str]:
        """解析日期字符串，适配CWE API返回的多种日期格式，返回标准YYYY-MM-DD"""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError:
            try:
                return datetime.strptime(date_str.split(" ")[0], "%Y-%m-%d").strftime("%Y-%m-%d")
            except:
                return None

    def _call_api(self, endpoint: str) -> Dict[str, Any]:
        """通用CWE API调用方法，封装所有请求异常"""
        url = f"{self.CWE_API_ROOT}/{endpoint}"
        try:
            response = requests.get(url, timeout=self.TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 404:
                raise ValueError(f"API端点无数据: {endpoint}") from e
            raise RuntimeError(f"API请求失败(HTTP {response.status_code}): {e}") from e
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"网络连接失败: {e}") from e

    def get_cwe_version(self) -> Dict:
        """
        数据版本、更新日期及对应数据量
        :return: {'ContentVersion': '4.19', 'ContentDate': '2025-12-11', 'TotalWeaknesses': 969, 'TotalCategories': 420, 'TotalViews': 58}
        """
        data = self._call_api("cwe/version")
        table = self.db['vuln_config_table']
        table.upsert({
            'name': "CWE",
            'version': data.get('ContentVersion'),
            'data_date': data.get('ContentDate')
        })
        return data

    def __str__(self):
        class_str = ""
        for key, value in self.get_cwe_version().items():
            class_str += f"{key}:{value};"
        return class_str[:-1]

    def _ids(self, cwe_ids: (str | List[str])) -> str:
        """

        :param cwe_ids:
        :return:
        """
        if isinstance(cwe_ids, (str|int)):
            cwe_ids = [cwe_ids]
        ids = list()
        for i in cwe_ids:
            if 'cwe_' in str(i).lower():
                ids.append(str(i).split('_')[0])
            else:
                ids.append(str(i))
        return ','.join(ids)

    def get_cwe_ids(self, cwe_ids: (str | List[str]), is_save=False) -> list[Dict[str, Any]]:
        """
        使用id获取数据
        :param cwe_ids:
        :param is_save: 是否保存到数据库
        :return:
        """
        data = self._call_api(f"cwe/{self._ids(cwe_ids)}")
        id_type = defaultdict(list)
        for i in data:
            if 'weakness' in i['Type']:
                id_type["weakness"].append(i['ID'])
            elif 'category' in i['Type']:
                id_type["category"].append(i['ID'])
            else:
                id_type["view"].append(i['ID'])
        result = list()
        for t, ids in id_type.items():
            if is_save:
                method_name = f"sync_cwe_{t}"
            else:
                method_name = f"get_cwe_{t}"
            method = getattr(self, method_name)
            mod_rel = method(ids)
            if mod_rel:
                result.extend(mod_rel)
        return result

    def get_cwe_category(self, cwe_ids: List[str]) -> List[Dict[str, Any]]:
        """调用API获取CWE分类数据"""
        data = self._call_api(f"cwe/category/{self._ids(cwe_ids)}")
        return [data] if isinstance(data, dict) and "ID" in data else data["Categories"]

    def get_cwe_weakness(self, cwe_ids: List[str]) -> List[Dict[str, Any]]:
        """调用API获取CWE弱点数据"""
        data = self._call_api(f"cwe/weakness/{self._ids(cwe_ids)}")
        return [data] if isinstance(data, dict) and "ID" in data else data['Weaknesses']

    def get_cwe_view(self, cwe_ids: List[str]) -> List[Dict[str, Any]]:
        """调用API获取CWE视图数据"""
        data = self._call_api(f"cwe/view/{self._ids(cwe_ids)}")
        return [data] if isinstance(data, dict) and "ID" in data else data['Views']

    def get_cwe_descendants(self, cwe_id: str) -> list[Dict[str, Any]]:
        """
        查询子级
        :param cwe_id:
        :return: {'Data': {'Type': 'base_weakness', 'ID': '489', 'ViewID': '1000'}, 'Children': [{'Data': {'Type': 'variant_weakness', 'ID': '11', 'ViewID': '1000'}, 'Children': None}]}
        """
        data = self._call_api(f"cwe/{cwe_id}/descendants")
        return data

    def get_cwe_children(self, cwe_id: str) -> list[Dict[str, Any]]:
        """
        查询所有子孙级
        :param cwe_id:
        :return: [{'Type': 'base_weakness', 'ID': '1336'}, {'Type': 'variant_weakness', 'ID': '95'}, {'Type': 'base_weakness', 'ID': '96'}]
        """
        data = self._call_api(f'cwe/{cwe_id}/children')
        return data

    def get_cwe_parents(self, cwe_id: str) -> list[Dict[str, Any]]:
        """
        查询所有父级
        :param cwe_id:
        :return: [{'Type': 'category', 'ID': '907', 'ViewID': '888'}]
        """
        data = self._call_api(f"cwe/{cwe_id}/parents")
        return data

    def get_cwe_ancestors(self, cwe_id: str) -> list[Dict[str, Any]]:
        """
        查询所有父级
        :param cwe_id:
        :return:
        """
        data = self._call_api(f'cwe/{cwe_id}/ancestors')
        return data

    # ===================== dataset 数据库操作核心方法 (所有入库逻辑都在这里) =====================
    def save_cwe_base(self, cwe_data: Dict[str, Any], content_type: str):
        """dataset 保存CWE基础信息：自动建表、自动去重更新，无需手动写SQL"""
        table = self.db['cwe_base']
        cwe_item = {
            "id": cwe_data["ID"],
            "cwe_id": "CWE-" + str(cwe_data["ID"]),
            "name": cwe_data["Name"],
            "content_type": content_type,
            "status": cwe_data["Status"],
            "summary": cwe_data.get("Summary", ""),
            "objective": cwe_data.get("Objective", ""),
            "abstraction": cwe_data.get("Abstraction", ""),
            "structure": cwe_data.get("Structure", ""),
            "description": cwe_data.get("Description", ""),
            "extended_description": cwe_data.get("Extended_Description", ""),
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        table.upsert(cwe_item, keys=['id'])
        logger.info(f"基础信息入库完成: CWE-{cwe_data['ID']}")

    def save_cwe_relationships(self, cwe_id: str, relationships: List[Dict[str, Any]]):
        """dataset 保存CWE关系数据"""
        if not relationships:
            return
        table = self.db['cwe_relationships']
        # 先删除旧数据，避免重复
        table.delete(cwe_id=cwe_id)
        for rel in relationships:
            rel_item = {
                "cwe_id": cwe_id,
                "related_cwe_id": rel.get("CWE_ID", rel.get("CweID", "")),
                "view_id": rel.get("View_ID", rel.get("ViewID", "")),
                "ordinal": rel.get("Ordinal", ""),
                "nature": rel.get("Nature", "")
            }
            table.insert(rel_item)
        logger.info(f"关系数据入库完成: CWE-{cwe_id} ({len(relationships)} 条)")

    def save_cwe_content_history(self, cwe_id: str, history_entries: List[Dict[str, Any]]):
        """dataset 保存CWE内容历史数据"""
        if not history_entries:
            return
        table = self.db['cwe_content_history']
        table.delete(cwe_id=cwe_id)
        for entry in history_entries:
            entry = entry if "Type" in entry else entry.get("ContentHistory", entry.get("Content_History", {}))
            hist_item = {
                "cwe_id": cwe_id,
                "entry_type": entry.get("Type", ""),
                "submission_name": entry.get("SubmissionName", entry.get("Submission_Name", "")),
                "submission_organization": entry.get("SubmissionOrganization",
                                                     entry.get("Submission_Organization", "")),
                "submission_date": self._parse_date(entry.get("SubmissionDate", entry.get("Submission_Date", ""))),
                "modification_name": entry.get("ModificationName", entry.get("Modification_Name", "")),
                "modification_organization": entry.get("ModificationOrganization",
                                                       entry.get("Modification_Organization", "")),
                "modification_date": self._parse_date(
                    entry.get("ModificationDate", entry.get("Modification_Date", ""))),
                "modification_comment": entry.get("ModificationComment", entry.get("Modification_Comment", "")),
                "modification_importance": entry.get("ModificationImportance",
                                                     entry.get("Modification_Importance", "")),
                "previous_entry_name": entry.get("PreviousEntryName", entry.get("Previous_Entry_Name", "")),
                "contribution_name": entry.get("ContributionName", entry.get("Contribution_Name", "")),
                "contribution_organization": entry.get("ContributionOrganization",
                                                       entry.get("Contribution_Organization", "")),
                "contribution_date": self._parse_date(
                    entry.get("ContributionDate", entry.get("Contribution_Date", ""))),
                "contribution_comment": entry.get("ContributionComment", entry.get("Contribution_Comment", "")),
                "submission_comment": entry.get("SubmissionComment", entry.get("Submission_Comment", "")),
                "submission_version": entry.get("SubmissionVersion", entry.get("Submission_Version", "")),
                "submission_release_date": self._parse_date(
                    entry.get("SubmissionReleaseDate", entry.get("Submission_Release_Date", "")))
            }
            table.insert(hist_item)
        logger.info(f"内容历史入库完成: CWE-{cwe_id}")

    def save_cwe_mapping_notes(self, cwe_id: str, mapping_notes: Dict[str, Any]):
        """dataset 保存CWE映射备注数据"""
        if not mapping_notes:
            return
        table = self.db['cwe_mapping_notes']
        note_item = {
            "cwe_id": cwe_id,
            "usage": mapping_notes.get("Usage", ""),
            "rationale": mapping_notes.get("Rationale", ""),
            "comments": mapping_notes.get("Comments", ""),
            "reasons": ",".join(mapping_notes.get("Reasons", [])) if isinstance(mapping_notes.get("Reasons"),
                                                                                list) else ""
        }
        table.upsert(note_item, keys=['cwe_id'])
        logger.info(f"映射备注入库完成: CWE-{cwe_id}")

    def save_cwe_taxonomy_mappings(self, cwe_id: str, taxonomy_mappings: List[Dict[str, Any]]):
        """dataset 保存CWE分类映射数据"""
        if not taxonomy_mappings:
            return
        table = self.db['cwe_taxonomy_mappings']
        table.delete(cwe_id=cwe_id)
        for mapping in taxonomy_mappings:
            map_item = {
                "cwe_id": cwe_id,
                "taxonomy_name": mapping.get("Taxonomy_Name", ""),
                "entry_name": mapping.get("Entry_Name", ""),
                "entry_id": mapping.get("Entry_ID", ""),
                "mapping_fit": mapping.get("Mapping_Fit", "")
            }
            table.insert(map_item)
        logger.info(f"分类映射入库完成: CWE-{cwe_id} ({len(taxonomy_mappings)} 条)")

    def save_cwe_audience(self, cwe_id: str, audience: List[Dict[str, Any]]):
        """dataset 保存CWE视图受众数据"""
        if not audience:
            return
        table = self.db['cwe_audience']
        table.delete(cwe_id=cwe_id)
        for item in audience:
            aud_item = {
                "cwe_id": cwe_id,
                "type": item.get("Type", ""),
                "description": item.get("Description", "")
            }
            table.insert(aud_item)
        logger.info(f"受众数据入库完成: CWE-{cwe_id} ({len(audience)} 条)")

    def save_cwe_members(self, cwe_id: str, members: List[Dict[str, Any]]):
        """dataset 保存CWE视图成员数据"""
        if not members:
            return
        table = self.db['cwe_members']
        table.delete(cwe_id=cwe_id)
        for member in members:
            mem_item = {
                "cwe_id": cwe_id,
                "member_cwe_id": member.get("CWE_ID", member.get("CweID", "")),
                "view_id": member.get("View_ID", member.get("ViewID", ""))
            }
            table.insert(mem_item)
        logger.info(f"成员数据入库完成: CWE-{cwe_id} ({len(members)} 条)")

    # ===================== 对外核心调用方法 =====================
    def sync_cwe_category(self, cwe_ids: List[str]):
        """同步CWE分类数据到MySQL"""
        category_data_list = self.get_cwe_category(cwe_ids)
        for category in category_data_list:
            self.save_cwe_base(category, "Category")
            self.save_cwe_relationships(category["ID"], category.get("Relationships", []))
            self.save_cwe_content_history(category["ID"],
                                          category.get("Content_History", category.get("ContentHistory", [])))
            self.save_cwe_mapping_notes(category["ID"], category.get("MappingNotes", {}))
            self.save_cwe_taxonomy_mappings(category["ID"], category.get("Taxonomy_Mappings", []))

    def sync_cwe_weakness(self, cwe_ids: List[str]):
        """同步CWE弱点数据到MySQL"""
        weakness_data_list = self.get_cwe_weakness(cwe_ids)
        for weakness in weakness_data_list:
            self.save_cwe_base(weakness, "Weakness")
            self.save_cwe_relationships(weakness["ID"], weakness.get("Relationships", []))
            self.save_cwe_content_history(weakness["ID"],
                                          weakness.get("Content_History", weakness.get("ContentHistory", [])))
            self.save_cwe_taxonomy_mappings(weakness["ID"], weakness.get("Taxonomy_Mappings", []))

    def sync_cwe_view(self, cwe_ids: List[str]):
        """同步CWE视图数据到MySQL"""
        view_data_list = self.get_cwe_view(cwe_ids)
        for view in view_data_list:
            self.save_cwe_base(view, "View")
            self.save_cwe_relationships(view["ID"], view.get("Relationships", []))
            self.save_cwe_content_history(view["ID"], view.get("Content_History", view.get("ContentHistory", [])))
            self.save_cwe_audience(view["ID"], view.get("Audience", []))
            self.save_cwe_members(view["ID"], view.get("Members", []))


class CWEDataManager(CWEDataAPI):
    def __init__(self):
        super().__init__()

    def query(self, ids: (int | List[int])):
        if isinstance(ids, int):
            ids = [ids]
        table = self.db['cwe_base']
        ids_copy = copy.deepcopy(ids)
        sql_data = table.find(id=ids)
        if sql_data:
            for row in sql_data:
                if row['cwe_id'].startswith('CWE-'):
                    ids_copy.remove(row['id'])
        if ids_copy:
            self.get_cwe_ids(ids_copy, is_save=True)
            sql_data = table.find(id=ids)
        return sql_data


# ==================== 使用示例 ====================
if __name__ == "__main__":
    # 1. 同级目录创建 .env 文件，内容如下，修改为你的MySQL信息：
    # MYSQL_HOST=localhost
    # MYSQL_PORT=3306
    # MYSQL_USER=root
    # MYSQL_PASSWORD=你的数据库密码
    # MYSQL_DB=cwe_db

    # 2. 初始化管理器 (dataset自动创建所有数据表，无需手动建表！)
    # cwe_manager = CWEDataAPI()
    # for i in range(1, 1435):
    #     try:
    #         result = cwe_manager.get_cwe_ids(str(i), is_save=True)
    #     except Exception as e:
    #         print(f"❌ 同步数据失败: {str(e)}")
    # try:
    #     # 示例1：同步CWE分类数据
    #     # category_ids = ["978", "950", "1238", "973"]
    #     # cwe_manager.sync_cwe_category(category_ids)
    #
    #     # 示例2：同步常见漏洞弱点数据(XSS+SQL注入+命令注入)
    #     cwe_manager.sync_cwe_weakness(["79", "89", "78"])
    #
    #     # 示例3：同步视图数据
    #     cwe_manager.sync_cwe_view(["1000", "888"])
    #
    # except Exception as e:
    #     print(f"❌ 同步数据失败: {str(e)}")
    # finally:
    #     cwe_manager.close()
    cc = CWEDataManager()
    for i in range(1, 1435):
        cc.query(i)
